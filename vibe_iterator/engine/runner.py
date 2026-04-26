"""Scan orchestrator — runs scanners, emits events, stores results."""

from __future__ import annotations

import asyncio
import importlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from vibe_iterator.config import Config
from vibe_iterator.scanners.base import Finding, ScanEvent, Severity

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Score constants                                                              #
# --------------------------------------------------------------------------- #

SEVERITY_DEDUCTIONS: dict[str, int] = {
    "critical": 20, "high": 10, "medium": 4, "low": 1, "info": 0,
}

STAGE_MAX_DEDUCTIONS: dict[str, int] = {
    "dev": 60,
    "pre-deploy": 200,
    "post-deploy": 120,
    "all": 250,
}

GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "A"), (75, "B"), (60, "C"), (45, "D"), (0, "F"),
]

# --------------------------------------------------------------------------- #
# Result dataclasses                                                           #
# --------------------------------------------------------------------------- #

@dataclass
class ScannerResult:
    """Per-scanner outcome recorded in ScanResult.scanner_results."""

    scanner_name: str
    status: str                      # "passed"|"findings"|"skipped"|"timeout"|"error"
    findings_count: int
    duration_seconds: float | None
    skip_reason: str | None = None


@dataclass
class FindingMark:
    """A developer's marking applied to a Finding."""

    finding_id: str
    status: str                      # "resolved"|"accepted_risk"|"false_positive"|"none"
    note: str | None = None


@dataclass
class ScanResult:
    """Full result of a completed (or in-progress) scan run."""

    scan_id: str
    stage: str
    target: str
    status: str                      # "running"|"completed"|"error"|"cancelled"
    started_at: str                  # ISO 8601
    completed_at: str | None
    findings: list[Finding]
    scanner_results: list[ScannerResult]   # ordered by execution
    finding_marks: list[FindingMark]
    score: int | None
    score_grade: str | None
    duration_seconds: float | None
    pages_crawled: list[dict]        # [{"url": str, "status_code": int}]
    requests_captured: dict          # {"total": int, "GET": int, ...}
    stack_detected: str
    stack_detection_source: str
    second_account_used: bool
    scanner_overrides_applied: list[str] | None


# --------------------------------------------------------------------------- #
# Scanner module registry                                                      #
# --------------------------------------------------------------------------- #

_SCANNER_MODULE_MAP: dict[str, str] = {
    "data_leakage":     "vibe_iterator.scanners.data_leakage",
    "rls_bypass":       "vibe_iterator.scanners.rls_bypass",
    "tier_escalation":  "vibe_iterator.scanners.tier_escalation",
    "bucket_limits":    "vibe_iterator.scanners.bucket_limits",
    "auth_check":       "vibe_iterator.scanners.auth_check",
    "client_tampering": "vibe_iterator.scanners.client_tampering",
    "sql_injection":    "vibe_iterator.scanners.sql_injection",
    "cors_check":       "vibe_iterator.scanners.cors_check",
    "xss_check":        "vibe_iterator.scanners.xss_check",
    "api_exposure":     "vibe_iterator.scanners.api_exposure",
}


def _load_scanner(name: str) -> Any:
    """Import and instantiate a scanner by name."""
    module_path = _SCANNER_MODULE_MAP[name]
    module = importlib.import_module(module_path)
    # Convention: each scanner module exposes a Scanner class
    return module.Scanner()


# --------------------------------------------------------------------------- #
# ScanRunner                                                                   #
# --------------------------------------------------------------------------- #

class ScanRunner:
    """Orchestrates the full scan lifecycle.

    Accepts an on_event callback so it can drive both the WebSocket (GUI mode)
    and stdout (headless mode) without knowing which it is talking to.
    """

    def __init__(
        self,
        config: Config,
        on_event: Callable[[ScanEvent], None],
        scanner_overrides: list[str] | None = None,
        browser_headless: bool = False,
    ) -> None:
        self.config = config
        self.on_event = on_event
        self.scanner_overrides = scanner_overrides
        self.browser_headless = browser_headless
        self._cancel_requested: bool = False
        self._active_task: asyncio.Task | None = None
        self._result: ScanResult | None = None

    def cancel(self) -> None:
        """Request cancellation. Engine stops after the current scanner finishes."""
        self._cancel_requested = True
        if self._active_task:
            self._active_task.cancel()

    def get_result(self) -> ScanResult | None:
        """Return the current or last completed ScanResult."""
        return self._result

    async def run(self, stage: str) -> ScanResult:
        """Execute all scanners for the given stage and return the ScanResult."""
        from vibe_iterator.crawler import browser as browser_mod
        from vibe_iterator.crawler import auth as auth_mod
        from vibe_iterator.crawler import navigator as nav_mod
        from vibe_iterator.listeners.network import NetworkListener
        from vibe_iterator.listeners.console import ConsoleListener
        from vibe_iterator.listeners.storage import StorageListener

        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        scan_start = time.monotonic()

        # ------------------------------------------------------------------ #
        # 1. Resolve scanner list                                             #
        # ------------------------------------------------------------------ #
        stage_scanners = self.config.scanners_for_stage(stage)
        if not stage_scanners:
            raise ValueError(f"Unknown stage '{stage}' or stage has no scanners configured.")

        if self.scanner_overrides is not None:
            invalid = [s for s in self.scanner_overrides if s not in stage_scanners]
            if invalid:
                raise ValueError(
                    f"Invalid scanner_overrides for stage '{stage}': {invalid}. "
                    f"Valid names: {stage_scanners}"
                )
            resolved = self.scanner_overrides
        else:
            resolved = stage_scanners

        # ------------------------------------------------------------------ #
        # Initialize result (status=running so 409 guard works immediately)  #
        # ------------------------------------------------------------------ #
        self._result = ScanResult(
            scan_id=scan_id,
            stage=stage,
            target=self.config.target,
            status="running",
            started_at=started_at,
            completed_at=None,
            findings=[],
            scanner_results=[],
            finding_marks=[],
            score=None,
            score_grade=None,
            duration_seconds=None,
            pages_crawled=[],
            requests_captured={"total": 0, "GET": 0, "POST": 0, "PUT": 0, "DELETE": 0, "PATCH": 0},
            stack_detected=self.config.stack.backend,
            stack_detection_source=self.config.stack.detection_source,
            second_account_used=False,
            scanner_overrides_applied=self.scanner_overrides,
        )

        self._emit("scan_started", {
            "stage": stage,
            "target": self.config.target,
            "scanner_count": len(resolved),
            "scanner_names": resolved,
            "pages": self.config.pages,
        })

        # ------------------------------------------------------------------ #
        # 2. Launch browser and attach listeners                             #
        # ------------------------------------------------------------------ #
        session = None
        network = NetworkListener()
        console = ConsoleListener()
        storage = StorageListener()

        try:
            session = browser_mod.launch(headless=self.browser_headless)
            network.attach(session)
            console.attach(session)

            # ---------------------------------------------------------------- #
            # 3. Authenticate                                                  #
            # ---------------------------------------------------------------- #
            self._emit("scanner_progress", {
                "scanner_name": "auth",
                "message": f"Authenticating as {_mask(self.config.test_email)}...",
                "level": "info",
            })
            try:
                auth_mod.login(session, self.config, account=1)
                self._emit("scanner_progress", {
                    "scanner_name": "auth",
                    "message": "✓ Authentication successful",
                    "level": "info",
                })
            except Exception as exc:
                self._emit("scan_error", {
                    "error_type": "target_unreachable",
                    "error": str(exc),
                    "recoverable": False,
                })
                self._result.status = "error"
                self._result.completed_at = datetime.now(timezone.utc).isoformat()
                return self._result

            # ---------------------------------------------------------------- #
            # 4. Crawl pages                                                   #
            # ---------------------------------------------------------------- #
            def _on_page(meta: Any) -> None:
                self._emit("page_navigated", {"url": meta.url, "status_code": meta.status_code})
                storage.capture(session)

            crawled_pages = nav_mod.crawl_pages(session, self.config, on_page=_on_page)
            self._result.pages_crawled = [
                {"url": page.url, "status_code": page.status_code} for page in crawled_pages
            ]

            # ---------------------------------------------------------------- #
            # 5. Load scanner instances                                        #
            # ---------------------------------------------------------------- #
            scanners: list[Any] = []
            for name in resolved:
                try:
                    scanners.append(_load_scanner(name))
                except Exception as exc:
                    logger.warning("Could not load scanner '%s': %s", name, exc)

            listeners = {"network": network, "console": console, "storage": storage}

            # ---------------------------------------------------------------- #
            # 6. Run each scanner                                              #
            # ---------------------------------------------------------------- #
            for idx, scanner in enumerate(scanners):
                if self._cancel_requested:
                    self._emit("scan_cancelled", {
                        "scanner_name_at_cancel": scanner.name,
                        "findings_so_far": len(self._result.findings),
                        "duration_seconds": time.monotonic() - scan_start,
                    })
                    self._result.status = "cancelled"
                    self._result.completed_at = datetime.now(timezone.utc).isoformat()
                    self._result.duration_seconds = time.monotonic() - scan_start
                    return self._result

                # Stack check
                if scanner.requires_stack != ["any"] and \
                        self.config.stack.backend not in scanner.requires_stack:
                    reason = f"Requires {scanner.requires_stack[0]} stack — detected: {self.config.stack.backend}"
                    self._emit("scanner_skipped", {"scanner_name": scanner.name, "reason": reason})
                    self._result.scanner_results.append(ScannerResult(
                        scanner_name=scanner.name, status="skipped",
                        findings_count=0, duration_seconds=None, skip_reason=reason,
                    ))
                    continue

                self._emit("scanner_started", {
                    "scanner_name": scanner.name,
                    "category": scanner.category,
                    "index": idx + 1,
                    "total": len(scanners),
                })

                scanner_start = time.monotonic()
                findings: list[Finding] = []

                try:
                    findings = await asyncio.wait_for(
                        asyncio.to_thread(scanner.run, session, listeners, self.config),
                        timeout=self.config.scanner_timeout_seconds,
                    )
                except asyncio.TimeoutError:
                    self._emit("scan_error", {
                        "error_type": "scanner_timeout",
                        "error": f"Scanner '{scanner.name}' exceeded {self.config.scanner_timeout_seconds}s",
                        "scanner_name": scanner.name,
                        "recoverable": True,
                    })
                    self._result.scanner_results.append(ScannerResult(
                        scanner_name=scanner.name, status="timeout",
                        findings_count=0, duration_seconds=self.config.scanner_timeout_seconds,
                    ))
                    continue
                except Exception as exc:
                    logger.exception("Scanner '%s' raised an exception", scanner.name)
                    self._emit("scan_error", {
                        "error_type": "scanner_exception",
                        "error": str(exc),
                        "scanner_name": scanner.name,
                        "recoverable": True,
                    })
                    self._result.scanner_results.append(ScannerResult(
                        scanner_name=scanner.name, status="error",
                        findings_count=0, duration_seconds=time.monotonic() - scanner_start,
                    ))
                    continue

                duration = time.monotonic() - scanner_start

                # Track second account usage
                if scanner.requires_second_account and self.config.second_account_configured:
                    self._result.second_account_used = True

                # Emit + store each finding
                for f in findings:
                    self._result.findings.append(f)
                    self._emit("finding", {
                        "finding_id": f.id,
                        "fingerprint": f.fingerprint,
                        "scanner": f.scanner,
                        "severity": f.severity.value,
                        "title": f.title,
                        "description": f.description,
                        "category": f.category,
                        "page": f.page,
                    })

                outcome = "passed" if not findings else "findings"
                self._emit("scanner_completed", {
                    "scanner_name": scanner.name,
                    "outcome": outcome,
                    "findings_count": len(findings),
                    "duration_seconds": round(duration, 2),
                })
                self._result.scanner_results.append(ScannerResult(
                    scanner_name=scanner.name, status=outcome,
                    findings_count=len(findings), duration_seconds=round(duration, 2),
                ))

            # ---------------------------------------------------------------- #
            # 7. Finalize                                                      #
            # ---------------------------------------------------------------- #
            self._result.requests_captured = network.summary()
            score, grade = compute_score(self._result.findings, stage)
            self._result.score = score
            self._result.score_grade = grade
            self._result.status = "completed"
            self._result.completed_at = datetime.now(timezone.utc).isoformat()
            self._result.duration_seconds = round(time.monotonic() - scan_start, 2)

            by_severity = _severity_counts(self._result.findings)
            self._emit("scan_completed", {
                "total_findings": len(self._result.findings),
                "by_severity": by_severity,
                "duration_seconds": self._result.duration_seconds,
                "score": score,
                "score_grade": grade,
                "scanners_run": sum(1 for r in self._result.scanner_results if r.status != "skipped"),
                "scanners_skipped": sum(1 for r in self._result.scanner_results if r.status == "skipped"),
            })

        except Exception as exc:
            logger.exception("Unrecoverable scan error")
            self._emit("scan_error", {
                "error_type": "browser_crash",
                "error": str(exc),
                "recoverable": False,
            })
            if self._result:
                self._result.status = "error"
                self._result.completed_at = datetime.now(timezone.utc).isoformat()
                self._result.duration_seconds = round(time.monotonic() - scan_start, 2)
        finally:
            if session:
                session.quit()
            try:
                network.detach()
                console.detach()
            except Exception:
                pass

        assert self._result is not None
        return self._result

    def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        event = ScanEvent.now(event_type, data)
        try:
            self.on_event(event)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Score computation                                                            #
# --------------------------------------------------------------------------- #

def compute_score(findings: list[Finding], stage: str) -> tuple[int, str]:
    """Compute a 0–100 score and letter grade from findings."""
    raw_deduction = sum(SEVERITY_DEDUCTIONS.get(f.severity.value, 0) for f in findings)
    stage_max = STAGE_MAX_DEDUCTIONS.get(stage, 200)
    normalized_deduction = min(100, int((raw_deduction / stage_max) * 100))
    score = max(0, 100 - normalized_deduction)
    grade = next(g for threshold, g in GRADE_THRESHOLDS if score >= threshold)
    return score, grade


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


def _mask(email: str) -> str:
    if "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    return local[:1] + "***@" + domain

# VIBE-ITERATOR — Runtime Security Testing for Vibe-Coded Apps

## What This Project Is

Vibe Iterator is an open-source, Selenium-based runtime security testing tool for web applications built on Supabase (and eventually other stacks). It targets developers who "vibe code" with AI assistants and ship apps without understanding the security implications.

Unlike static code-scanning tools (e.g., raroque/vibe-security-skill), Vibe Iterator **actually runs the app**, logs in as a test user, tampers with client-side data, inspects devtools/network traffic, and **proves whether vulnerabilities are exploitable** — not just theoretically present.

**Interface:** A local web dashboard on `localhost:3001` styled as a hacker-themed security control center — select scan stage, watch live scan progress with real-time terminal output, then explore results with copy-paste LLM fix prompts.

---

## Sub-Documents

Read these before building. Each covers a specific domain:

| Doc | What It Covers |
|-----|---------------|
| `docs/STACK.md` | Tech stack choices, dependencies, and why each was chosen |
| `docs/DASHBOARD.md` | Full GUI specification — pages, layout, visual language, WebSocket protocol |
| `docs/SCANNERS.md` | Scanner interface contract, BaseScanner pattern, Finding dataclass, all scanner descriptions |
| `docs/ENGINE.md` | Scan engine architecture, ScanRunner class, event system, dual-mode (GUI vs CLI) |
| `docs/CONFIG.md` | `.env` schema, `vibe-iterator.config.yaml` schema, stage profiles |
| `docs/STANDARDS.md` | Coding standards, design decisions, guardrails |
| `docs/PHASES.md` | Build phases with step-by-step order, test requirements, and "done when" checkpoints |

---

## Architecture Overview

```
vibe-iterator/
├── CLAUDE.md                    # This file (read first)
├── README.md                    # User-facing docs
├── pyproject.toml               # Package config (setuptools/pip)
├── .env.example                 # Template for user secrets
├── vibe_iterator/
│   ├── __init__.py
│   ├── cli.py                   # Click CLI entry point (GUI mode + headless mode)
│   ├── config.py                # Load .env + YAML config, validate required fields
│   ├── server/
│   │   ├── __init__.py
│   │   ├── app.py               # FastAPI app — serves dashboard, WebSocket, REST API
│   │   ├── websocket.py         # WebSocket manager — broadcast scan events
│   │   ├── routes.py            # API routes: start scan, get results, export report
│   │   └── static/
│   │       ├── index.html       # Dashboard Home — stage selector, scan launcher
│   │       ├── scan.html        # Live Scan Progress — terminal + findings feed
│   │       ├── results.html     # Results Dashboard — findings, evidence, LLM prompts
│   │       ├── css/
│   │       │   └── dashboard.css
│   │       └── js/
│   │           ├── app.js
│   │           ├── websocket.js
│   │           └── clipboard.js
│   ├── crawler/
│   │   ├── __init__.py
│   │   ├── browser.py           # Selenium + CDP session manager
│   │   ├── auth.py              # Login flows (email/password, OAuth stubs)
│   │   └── navigator.py         # Page-by-page crawl logic
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── base.py              # BaseScanner abstract class
│   │   ├── rls_bypass.py        # Supabase RLS policy testing
│   │   ├── tier_escalation.py   # Subscription tier manipulation
│   │   ├── bucket_limits.py     # Storage bucket upload limit bypass
│   │   ├── data_leakage.py      # Tokens, UUIDs, PII in devtools/network
│   │   ├── sql_injection.py     # Extensive SQLi — PostgREST, ORM bypass, blind injection
│   │   ├── auth_check.py        # Extensive auth — tokens, sessions, login, bypass vectors
│   │   ├── client_tampering.py  # localStorage/cookie manipulation
│   │   ├── cors_check.py        # CORS misconfiguration
│   │   ├── xss_check.py         # Reflected, stored, DOM-based XSS
│   │   └── api_exposure.py      # Unprotected endpoints, mass assignment
│   ├── listeners/
│   │   ├── __init__.py
│   │   ├── network.py           # CDP Network domain listener
│   │   ├── console.py           # CDP Console/Log domain listener
│   │   └── storage.py           # localStorage, sessionStorage, cookies
│   ├── engine/
│   │   ├── __init__.py
│   │   └── runner.py            # Scan orchestrator — emits events via callback
│   ├── evidence/
│   │   ├── __init__.py
│   │   └── collector.py         # Screenshots, network logs, payload/response pairs
│   ├── report/
│   │   ├── __init__.py
│   │   ├── generator.py         # Jinja2 report builder (exportable HTML)
│   │   ├── templates/
│   │   │   └── report.html.j2   # Standalone export report template
│   │   └── prompt_builder.py    # Generate LLM fix prompts per finding
│   └── utils/
│       ├── __init__.py
│       └── supabase_helpers.py  # CDP snippet builders, PostgREST URL parser, session extractor (used by rls_bypass, tier_escalation, bucket_limits)
├── tests/
│   ├── conftest.py
│   ├── test_scanners/
│   ├── test_listeners/
│   └── test_server/
└── docs/                        # Sub-documents (see table above)
    ├── STACK.md
    ├── DASHBOARD.md
    ├── SCANNERS.md
    ├── ENGINE.md
    ├── CONFIG.md
    ├── STANDARDS.md
    └── PHASES.md
```

---

## Naming

- **Package name:** `vibe-iterator`
- **CLI command:** `vibe-iterator`
- **PyPI:** `vibe-iterator`
- **GitHub repo:** TBD (Francisco's choice)
- **Dashboard URL:** `http://localhost:3001`
- **Report file default:** `vibe-iterator-report-{timestamp}.html`

---

## References

- Chris Raroque's vibe-security-skill (static code scanning complement): https://github.com/raroque/vibe-security-skill
- Supabase security video by Chris Raroque (subscription tier/bucket manipulation): https://youtu.be/tK4NQtzfZbM
- Snyk article on Claude security skills: https://snyk.io/articles/top-claude-skills-cybersecurity-hacking-vulnerability-scanning/
- Selenium CDP docs: https://www.selenium.dev/documentation/webdriver/bidirectional/chrome_devtools/
- SecSkills pentesting methodology (web-app-security, api-security-testing): https://github.com/trilwu/secskills

"""Chrome browser session manager — one instance per scan run."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

logger = logging.getLogger(__name__)


@dataclass
class BrowserSession:
    """Wraps a single Selenium Chrome driver for a scan run.

    One BrowserSession is created per scan and shared across all scanners.
    Never create a new session mid-scan.
    """

    driver: webdriver.Chrome
    _cdp_listeners: list[tuple[str, Any]] = field(default_factory=list, repr=False)

    def execute_cdp(self, cmd: str, params: dict | None = None) -> Any:
        """Execute a raw CDP command and return the result."""
        return self.driver.execute_cdp_cmd(cmd, params or {})

    def evaluate(self, script: str) -> Any:
        """Execute JavaScript in the current page context via CDP Runtime.evaluate."""
        result = self.execute_cdp(
            "Runtime.evaluate",
            {"expression": script, "returnByValue": True, "awaitPromise": True},
        )
        if result.get("exceptionDetails"):
            details = result["exceptionDetails"]
            raise RuntimeError(f"CDP Runtime.evaluate raised: {details.get('text', details)}")
        return result.get("result", {}).get("value")

    def navigate(self, url: str) -> None:
        """Navigate to a URL and wait for page load."""
        self.driver.get(url)

    def current_url(self) -> str:
        """Return the current page URL."""
        return self.driver.current_url

    def quit(self) -> None:
        """Close Chrome. Always called in the scan engine's finally block."""
        try:
            self.driver.quit()
        except Exception:
            pass  # Already closed — ignore


def launch(*, headless: bool = False) -> BrowserSession:
    """Launch Chrome with CDP enabled and return a BrowserSession.

    Selenium Manager (bundled with Selenium 4.6+) handles ChromeDriver
    automatically — no separate chromedriver install required.

    Args:
        headless: Run Chrome without a visible window. False during
                  GUI mode so the developer can watch the scan.
    """
    options = Options()

    if headless:
        options.add_argument("--headless=new")

    # Required for CDP and security testing
    options.add_argument("--remote-debugging-port=9222")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-web-security")           # allow cross-origin CDP inspection
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-popup-blocking")
    options.add_argument("--disable-blink-features=AutomationControlled")

    # Suppress Chrome's "Chrome is being controlled by automated software" bar
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)

    # Keep a clean profile per run to avoid cross-scan state leakage
    options.add_argument("--incognito")

    service = Service()  # Selenium Manager resolves the binary path
    driver = webdriver.Chrome(service=service, options=options)

    # Enable CDP Network and Console domains so listeners can attach
    driver.execute_cdp_cmd("Network.enable", {})
    driver.execute_cdp_cmd("Console.enable", {})

    logger.info("Chrome launched — CDP connected")
    return BrowserSession(driver=driver)

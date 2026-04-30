"""Unit tests for browser session and crawler helpers."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from selenium.common.exceptions import NoSuchElementException, TimeoutException

from vibe_iterator.crawler import auth, navigator
from vibe_iterator.crawler import browser
from vibe_iterator.crawler.browser import BrowserSession


def test_browser_session_evaluate_returns_cdp_value() -> None:
    driver = MagicMock()
    driver.execute_cdp_cmd.return_value = {"result": {"value": 42}}
    session = BrowserSession(driver=driver)

    assert session.evaluate("1 + 1") == 42
    driver.execute_cdp_cmd.assert_called_once_with(
        "Runtime.evaluate",
        {"expression": "1 + 1", "returnByValue": True, "awaitPromise": True},
    )


def test_browser_session_evaluate_raises_on_exception_details() -> None:
    driver = MagicMock()
    driver.execute_cdp_cmd.return_value = {"exceptionDetails": {"text": "ReferenceError"}}
    session = BrowserSession(driver=driver)

    try:
        session.evaluate("missing")
    except RuntimeError as exc:
        assert "ReferenceError" in str(exc)
    else:
        raise AssertionError("Expected RuntimeError")


def test_browser_session_quit_ignores_closed_driver() -> None:
    driver = MagicMock()
    driver.quit.side_effect = RuntimeError("closed")
    BrowserSession(driver=driver).quit()
    driver.quit.assert_called_once()


def test_launch_uses_dynamic_debug_port_and_preserves_web_security(monkeypatch) -> None:
    monkeypatch.delenv("VIBE_ITERATOR_CHROME_DEBUG_PORT", raising=False)
    monkeypatch.delenv("VIBE_ITERATOR_DISABLE_WEB_SECURITY", raising=False)
    driver = MagicMock()

    with patch("vibe_iterator.crawler.browser.webdriver.Chrome", return_value=driver) as chrome:
        session = browser.launch(headless=True)

    options = chrome.call_args.kwargs["options"]
    assert "--remote-debugging-port=0" in options.arguments
    assert "--disable-web-security" not in options.arguments
    assert session.driver is driver
    driver.execute_cdp_cmd.assert_any_call("Network.enable", {})
    driver.execute_cdp_cmd.assert_any_call("Console.enable", {})


def test_auth_second_account_skip_does_not_navigate() -> None:
    session = MagicMock()
    config = SimpleNamespace(second_account_configured=False)

    auth.login(session, config, account=2)

    session.navigate.assert_not_called()


def test_auth_login_fills_form_and_waits_for_navigation() -> None:
    session = MagicMock()
    session.driver.current_url = "http://localhost:3000/dashboard"
    config = SimpleNamespace(
        target="http://localhost:3000",
        test_email="test@example.com",
        test_password="pw",
        second_account_configured=False,
    )
    email_field = MagicMock()
    password_field = MagicMock()
    submit = MagicMock()
    session.driver.find_element.side_effect = [password_field, submit]

    wait = MagicMock()
    wait.until.side_effect = [email_field, True]

    with patch("vibe_iterator.crawler.auth.WebDriverWait", return_value=wait):
        auth.login(session, config)

    session.navigate.assert_called_once_with("http://localhost:3000/login")
    email_field.send_keys.assert_called_once_with("test@example.com")
    password_field.send_keys.assert_called_once_with("pw")
    submit.click.assert_called_once()


def test_fill_login_form_raises_when_password_field_missing() -> None:
    session = MagicMock()
    email_field = MagicMock()
    wait = MagicMock()
    wait.until.return_value = email_field
    session.driver.find_element.side_effect = NoSuchElementException("no password")

    with patch("vibe_iterator.crawler.auth.WebDriverWait", return_value=wait):
        with pytest.raises(NoSuchElementException):
            auth._fill_login_form(session, email="test@example.com", password="pw")


def test_wait_for_auth_reports_rejected_credentials() -> None:
    session = MagicMock()
    session.driver.page_source = "Invalid password"
    wait = MagicMock()
    wait.until.side_effect = TimeoutException("timeout")

    with patch("vibe_iterator.crawler.auth.WebDriverWait", return_value=wait):
        with pytest.raises(auth.AuthError, match="credentials rejected"):
            auth._wait_for_auth(session, "http://localhost:3000")


def test_auth_helper_masks_and_resolves_login_url() -> None:
    assert auth._resolve_login_url("http://localhost:3000/") == "http://localhost:3000/login"
    assert auth._mask_email("test@example.com") == "t***@example.com"
    assert auth._mask_email("not-an-email") == "***"


def test_navigator_build_url_normalizes_slashes() -> None:
    assert navigator._build_url("http://localhost:3000/", "dashboard") == "http://localhost:3000/dashboard"
    assert navigator._build_url("http://localhost:3000", "/settings") == "http://localhost:3000/settings"

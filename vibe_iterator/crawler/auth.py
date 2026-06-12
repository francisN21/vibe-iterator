"""Authentication helpers — login flows for primary and secondary test accounts."""

from __future__ import annotations

import logging

from selenium.common.exceptions import (
    ElementClickInterceptedException,
    NoSuchElementException,
    TimeoutException,
    WebDriverException,
)
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from vibe_iterator.config import Config
from vibe_iterator.crawler.browser import BrowserSession

logger = logging.getLogger(__name__)

_LOGIN_TIMEOUT = 15  # seconds to wait for login page elements
_AUTH_COOKIE_MARKERS = ("session", "auth", "token", "jwt", "sb-", "supabase", "clerk")
_AUTH_STORAGE_MARKERS = ("session", "auth", "token", "jwt", "supabase", "firebase", "clerk", "nextauth")
_CONSENT_BUTTON_TEXTS = (
    "deny optional",
    "reject all",
    "accept all",
    "accept",
    "i agree",
    "agree",
    "continue",
    "ok",
)


class AuthError(Exception):
    """Raised when authentication fails and cannot be recovered."""


def login(session: BrowserSession, config: Config, *, account: int = 1) -> None:
    """Authenticate the browser session as a test account.

    Args:
        session: Active BrowserSession to authenticate.
        config:  Loaded Config containing credentials.
        account: 1 = primary account, 2 = second test account.
                 Account 2 is silently skipped if not configured.

    The engine calls login(account=1) once at scan start.
    Scanners that need account 2 call login(account=2) themselves
    and restore the primary session with login(account=1) before returning.
    """
    if account == 2:
        if not config.second_account_configured:
            logger.info("Second test account not configured — skipping account=2 login")
            return
        email = config.test_email_2
        password = config.test_password_2
    else:
        email = config.test_email
        password = config.test_password

    assert email and password  # guaranteed by config validation / second_account_configured check

    login_url = _resolve_login_url(config.target)
    logger.info("Authenticating as %s", _mask_email(email))

    session.navigate(login_url)

    try:
        _fill_login_form(session, email=email, password=password)
    except (NoSuchElementException, TimeoutException) as exc:
        raise AuthError(
            f"Login form not found at {login_url}. "
            "Check that the login page path is correct and the app is running."
        ) from exc

    _wait_for_auth(session, config.target)
    logger.info("Authentication successful (%s)", _mask_email(email))


def _resolve_login_url(target: str) -> str:
    """Return the login URL from the target base URL."""
    return target.rstrip("/") + "/login"


def _fill_login_form(session: BrowserSession, *, email: str, password: str) -> None:
    """Find and fill the login form fields, then submit."""
    driver = session.driver
    wait = WebDriverWait(driver, _LOGIN_TIMEOUT)

    # Try common email field selectors in order of specificity
    email_field = None
    for selector in [
        (By.CSS_SELECTOR, "input[type='email']"),
        (By.CSS_SELECTOR, "input[name='email']"),
        (By.CSS_SELECTOR, "input[id='email']"),
        (By.CSS_SELECTOR, "input[autocomplete='email']"),
        (By.CSS_SELECTOR, "input[type='text']"),
    ]:
        try:
            email_field = wait.until(EC.presence_of_element_located(selector))
            break
        except TimeoutException:
            continue

    if email_field is None:
        raise NoSuchElementException("No email input found on login page")

    password_field = None
    for selector in [
        (By.CSS_SELECTOR, "input[type='password']"),
        (By.CSS_SELECTOR, "input[name='password']"),
        (By.CSS_SELECTOR, "input[id='password']"),
    ]:
        try:
            password_field = driver.find_element(*selector)
            break
        except NoSuchElementException:
            continue

    if password_field is None:
        raise NoSuchElementException("No password input found on login page")

    email_field.clear()
    email_field.send_keys(email)
    password_field.clear()
    password_field.send_keys(password)

    # Submit: try a submit button, fall back to Enter key
    try:
        submit = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        _submit_login_form(driver, password_field, submit)
    except NoSuchElementException:
        password_field.submit()


def _submit_login_form(driver: object, password_field: object, submit: object) -> None:
    try:
        submit.click()
        return
    except ElementClickInterceptedException:
        if _dismiss_blocking_consent_banners(driver):
            try:
                submit.click()
                return
            except ElementClickInterceptedException:
                pass

    try:
        driver.execute_script("arguments[0].click();", submit)
    except WebDriverException:
        password_field.submit()


def _dismiss_blocking_consent_banners(driver: object) -> bool:
    try:
        buttons = driver.find_elements(By.CSS_SELECTOR, "button")
    except Exception:
        return False

    for button in buttons:
        text = str(getattr(button, "text", "") or "").strip().lower()
        if text not in _CONSENT_BUTTON_TEXTS:
            continue
        try:
            button.click()
            return True
        except WebDriverException:
            continue
    return False


def _wait_for_auth(session: BrowserSession, target: str) -> None:
    """Wait until login either navigates away or leaves browser auth state."""
    login_url = _resolve_login_url(target)
    driver = session.driver

    try:
        WebDriverWait(driver, _LOGIN_TIMEOUT).until(lambda d: _looks_authenticated(d, login_url))
    except TimeoutException:
        if _has_browser_auth_state(driver):
            return

        # Still on login page — check for visible error messages
        page_source = driver.page_source.lower()
        if any(kw in page_source for kw in ["invalid", "incorrect", "wrong", "failed"]):
            raise AuthError(
                "Login failed — credentials rejected by the application. "
                "Check VIBE_ITERATOR_TEST_EMAIL and VIBE_ITERATOR_TEST_PASSWORD."
            )
        csp_errors = _csp_script_blockers(driver)
        if csp_errors:
            raise AuthError(
                "Login could not complete because the browser reported Content Security Policy script blocking "
                "on the login page. The app appears to block its own JavaScript, so the login handler never "
                f"created a session. First CSP error: {csp_errors[0]}"
            )

        raise AuthError(
            f"Login timed out after {_LOGIN_TIMEOUT}s. "
            "The page did not navigate away from the login URL and no browser session marker was found. "
            f"Observed: {_auth_state_summary(driver)}"
        )


def _looks_authenticated(driver: object, login_url: str) -> bool:
    current_url = getattr(driver, "current_url", "")
    if isinstance(current_url, str) and current_url != login_url and "/login" not in current_url:
        return True
    return _has_browser_auth_state(driver)


def _has_browser_auth_state(driver: object) -> bool:
    return bool(_auth_cookie_names(driver) or _auth_storage_keys(driver))


def _auth_cookie_names(driver: object) -> list[str]:
    try:
        cookies = driver.get_cookies()
    except Exception:
        return []
    if not isinstance(cookies, list):
        return []

    names: list[str] = []
    for cookie in cookies:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name", ""))
        value = str(cookie.get("value", ""))
        if not name or not value:
            continue
        lowered = name.lower()
        if any(marker in lowered for marker in _AUTH_COOKIE_MARKERS):
            names.append(name)
    return names


def _auth_storage_keys(driver: object) -> list[str]:
    try:
        storage = driver.execute_script(
            """
            return {
              localStorage: Object.keys(window.localStorage || {}),
              sessionStorage: Object.keys(window.sessionStorage || {})
            };
            """
        )
    except Exception:
        return []
    if not isinstance(storage, dict):
        return []

    keys: list[str] = []
    for bucket in ("localStorage", "sessionStorage"):
        raw_keys = storage.get(bucket, [])
        if not isinstance(raw_keys, list):
            continue
        for key in raw_keys:
            text = str(key)
            lowered = text.lower()
            if any(marker in lowered for marker in _AUTH_STORAGE_MARKERS):
                keys.append(f"{bucket}:{text}")
    return keys


def _auth_state_summary(driver: object) -> str:
    current_url = getattr(driver, "current_url", "?")
    cookies = _auth_cookie_names(driver)
    storage = _auth_storage_keys(driver)
    return f"current_url={current_url!r}, auth_cookies={cookies}, auth_storage_keys={storage}"


def _csp_script_blockers(driver: object) -> list[str]:
    try:
        logs = driver.get_log("browser")
    except Exception:
        return []
    if not isinstance(logs, list):
        return []

    errors: list[str] = []
    for entry in logs:
        if not isinstance(entry, dict):
            continue
        message = str(entry.get("message", ""))
        lowered = message.lower()
        if "content security policy" not in lowered:
            continue
        if "script-src" not in lowered and "script-src-elem" not in lowered:
            continue
        if "violates" not in lowered and "blocked" not in lowered:
            continue
        errors.append(message[:500])
    return errors


def _mask_email(email: str) -> str:
    """Return a partially masked email for safe log output."""
    if "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    return local[:1] + "***@" + domain

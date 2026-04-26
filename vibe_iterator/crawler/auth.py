"""Authentication helpers — login flows for primary and secondary test accounts."""

from __future__ import annotations

import logging
import time
from typing import Protocol

from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from vibe_iterator.config import Config
from vibe_iterator.crawler.browser import BrowserSession

logger = logging.getLogger(__name__)

_LOGIN_TIMEOUT = 15  # seconds to wait for login page elements


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
        submit.click()
    except NoSuchElementException:
        password_field.submit()


def _wait_for_auth(session: BrowserSession, target: str) -> None:
    """Wait until the browser navigates away from the login page."""
    login_url = _resolve_login_url(target)
    driver = session.driver

    try:
        WebDriverWait(driver, _LOGIN_TIMEOUT).until(
            lambda d: d.current_url != login_url and "/login" not in d.current_url
        )
    except TimeoutException:
        # Still on login page — check for visible error messages
        page_source = driver.page_source.lower()
        if any(kw in page_source for kw in ["invalid", "incorrect", "wrong", "failed"]):
            raise AuthError(
                "Login failed — credentials rejected by the application. "
                "Check VIBE_ITERATOR_TEST_EMAIL and VIBE_ITERATOR_TEST_PASSWORD."
            )
        raise AuthError(
            f"Login timed out after {_LOGIN_TIMEOUT}s. "
            "The page did not navigate away from the login URL."
        )


def _mask_email(email: str) -> str:
    """Return a partially masked email for safe log output."""
    if "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    return local[:1] + "***@" + domain

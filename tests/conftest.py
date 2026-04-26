"""Shared pytest fixtures for vibe-iterator tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from vibe_iterator.config import Config, StackConfig


@pytest.fixture
def mock_config() -> Config:
    """Minimal valid Config for unit tests — no live browser or .env required."""
    return Config(
        target="http://localhost:3000",
        test_email="test@example.com",
        test_password="testpassword123",
        test_email_2="test2@example.com",
        test_password_2="testpassword456",
        supabase_url=None,
        supabase_anon_key=None,
        pages=["/", "/login", "/dashboard"],
        stages={
            "dev": ["data_leakage", "auth_check", "client_tampering"],
            "pre-deploy": ["data_leakage", "auth_check"],
            "post-deploy": ["cors_check", "data_leakage"],
            "all": ["data_leakage", "auth_check", "client_tampering", "cors_check"],
        },
        stack=StackConfig(backend="supabase", auth="supabase-auth", storage="supabase", detection_source="manually-configured"),
        port=3001,
        scanner_timeout_seconds=60,
    )


@pytest.fixture
def mock_config_no_second_account(mock_config: Config) -> Config:
    """Config without a second test account."""
    mock_config.test_email_2 = None
    mock_config.test_password_2 = None
    return mock_config


@pytest.fixture
def mock_browser_session() -> MagicMock:
    """Mock BrowserSession — no live Chrome required."""
    from vibe_iterator.crawler.browser import BrowserSession

    session = MagicMock(spec=BrowserSession)
    session.current_url.return_value = "http://localhost:3000/dashboard"
    session.evaluate.return_value = None
    session.execute_cdp.return_value = {}

    # Mock driver with basic WebDriver interface
    driver = MagicMock()
    driver.current_url = "http://localhost:3000/dashboard"
    driver.title = "Test App"
    driver.get_cookies.return_value = []
    session.driver = driver

    return session

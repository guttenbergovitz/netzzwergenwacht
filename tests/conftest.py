"""Pytest configuration and shared fixtures."""

from pathlib import Path

import pytest


@pytest.fixture
def sample_url():
    """Sample URL for testing."""
    return "https://example.com"


@pytest.fixture
def fixtures_dir():
    """Path to test fixtures directory."""
    return Path(__file__).parent / "fixtures"

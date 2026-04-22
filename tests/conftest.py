"""
Pytest configuration for async tests.
"""

import pytest


@pytest.fixture(scope="session")
def anyio_backend():
    """Use anyio as async backend."""
    return "asyncio"


# Configure pytest-asyncio
def pytest_configure(config):
    """Configure pytest settings."""
    config.option.asyncio_mode = "auto"
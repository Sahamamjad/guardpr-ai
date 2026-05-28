"""Pytest configuration."""

import pytest


@pytest.fixture
def sample_secret_text():
    return "password=MySecretPassword123"

"""Pytest configuration and fixtures."""

import os

import pytest


@pytest.fixture(autouse=True)
def clear_env_vars():
    """Clear environment variables before each test."""
    env_vars_to_clear = [
        "UNIFI_URL",
        "UNIFI_USERNAME",
        "UNIFI_PASSWORD",
        "UNIFI_API_KEY",
        "TRAEFIK_IP",
        "TRAEFIK_API_URL",
        "DNS_RECORD_TYPE",
        "LOG_LEVEL",
        "FULL_SYNC_INTERVAL",
        "IGNORE_SSL_WARNINGS",
    ]

    # Save original values
    original_values = {}
    for var in env_vars_to_clear:
        if var in os.environ:
            original_values[var] = os.environ[var]
            del os.environ[var]

    yield

    # Restore original values
    for var in env_vars_to_clear:
        if var in os.environ:
            del os.environ[var]
        if var in original_values:
            os.environ[var] = original_values[var]

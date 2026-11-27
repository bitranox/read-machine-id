"""Domain error types: instantiation and message preservation."""

from __future__ import annotations

import pytest

from read_machine_id.domain.errors import ConfigurationError


@pytest.mark.os_agnostic
def test_configuration_error_preserves_message() -> None:
    """Instantiation stores the message for display."""
    exc = ConfigurationError("No configuration profile named 'staging'")
    assert str(exc) == "No configuration profile named 'staging'"

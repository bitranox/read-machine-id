"""Domain-specific exceptions for typed error handling at boundaries."""

from __future__ import annotations


class ConfigurationError(Exception):
    """Missing, invalid, or incomplete configuration.

    Raised when required configuration values are absent, malformed, or
    logically inconsistent. Typically caught at CLI boundaries to provide
    user-friendly error messages.

    Example:
        >>> from read_machine_id.domain.errors import ConfigurationError
        >>> err = ConfigurationError("No configuration profile named 'staging'")
        >>> str(err)
        "No configuration profile named 'staging'"
    """


__all__ = [
    "ConfigurationError",
]

"""Type-safe domain enums: output formats, deployment targets, the OS a reading was taken on."""

from __future__ import annotations

from enum import StrEnum


class OutputFormat(StrEnum):
    """Output format options for configuration display.

    Defines valid output format choices for the config command.
    Inherits from str to allow direct string comparison and Click integration.

    Attributes:
        HUMAN: Human-readable TOML-like output format.
        JSON: Machine-readable JSON output format.

    Example:
        >>> OutputFormat.HUMAN.value
        'human'
        >>> OutputFormat.JSON == "json"
        True
    """

    HUMAN = "human"
    JSON = "json"


class DeployTarget(StrEnum):
    """Configuration deployment target layers.

    Defines valid target layers for configuration file deployment.
    Inherits from str to allow direct string comparison and Click integration.

    Attributes:
        APP: System-wide application configuration (requires privileges).
        HOST: System-wide host-specific configuration (requires privileges).
        USER: User-specific configuration (~/.config on Linux).

    Example:
        >>> DeployTarget.USER.value
        'user'
        >>> DeployTarget.APP == "app"
        True
    """

    APP = "app"
    HOST = "host"
    USER = "user"


class MachineOs(StrEnum):
    """The operating system a reading was taken on, as ``meta.os`` records it.

    Example:
        >>> MachineOs.LINUX.value
        'linux'
    """

    WINDOWS = "windows"
    LINUX = "linux"


__all__ = [
    "DeployTarget",
    "MachineOs",
    "OutputFormat",
]

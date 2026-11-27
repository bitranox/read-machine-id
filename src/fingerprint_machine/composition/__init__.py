"""Composition root wiring adapters to application ports."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..adapters.config.deploy import deploy_configuration
from ..adapters.config.display import display_config

# Configuration services
from ..adapters.config.loader import get_config, get_default_config_path

# Machine sources
from ..adapters.cpuid import NativeCpuid
from ..adapters.linux.sysfs import SysfsLinuxSource

# Logging services
from ..adapters.logging.setup import check_logging_config, init_logging
from ..adapters.windows.platform import PwshpyPlatformSource
from ..adapters.windows.registry import LibRegistrySource
from ..application.machine_ports import LinuxSources, MachineSources, WindowsSources
from ..domain.machine_errors import UnsupportedPlatformError

# Static conformance assertions - pyright verifies that each adapter function
# structurally satisfies its corresponding Protocol at type-check time.
if TYPE_CHECKING:
    from collections.abc import Callable

    from ..application.machine_ports import CpuidSource, LinuxSource, PlatformSource, RegistrySource
    from ..application.ports import (
        CheckLoggingConfig,
        DeployConfiguration,
        DisplayConfig,
        GetConfig,
        GetDefaultConfigPath,
        InitLogging,
    )

    _assert_get_config: GetConfig = get_config
    _assert_get_default_config_path: GetDefaultConfigPath = get_default_config_path
    _assert_deploy_configuration: DeployConfiguration = deploy_configuration
    _assert_display_config: DisplayConfig = display_config
    _assert_init_logging: InitLogging = init_logging
    _assert_check_logging_config: CheckLoggingConfig = check_logging_config
    _assert_platform: PlatformSource = PwshpyPlatformSource()
    _assert_registry: RegistrySource = LibRegistrySource()
    _assert_linux: LinuxSource = SysfsLinuxSource()
    _assert_cpuid: CpuidSource = NativeCpuid()


@dataclass(frozen=True, slots=True)
class AppServices:
    """Frozen container holding all application port implementations."""

    get_config: GetConfig
    get_default_config_path: GetDefaultConfigPath
    deploy_configuration: DeployConfiguration
    display_config: DisplayConfig
    init_logging: InitLogging
    check_logging_config: CheckLoggingConfig
    #: Returns the sources of the machine to read; raises UnsupportedPlatformError where none exist.
    machine_sources: Callable[[], MachineSources]


def machine_sources() -> MachineSources:
    """Return the sources of the machine this runs on: Windows or Linux.

    Raises:
        UnsupportedPlatformError: neither Windows nor Linux; there is nothing this tool can read.
    """
    if sys.platform == "win32":
        return WindowsSources(platform=PwshpyPlatformSource(), registry=LibRegistrySource(), cpuid=NativeCpuid())
    if sys.platform.startswith("linux"):
        return LinuxSources(system=SysfsLinuxSource(), cpuid=NativeCpuid())
    msg = f"reading a machine needs Windows or Linux; this is {sys.platform}. 'compare' works everywhere."
    raise UnsupportedPlatformError(msg)


def build_production() -> AppServices:
    """Wire production adapters into an AppServices container."""
    return AppServices(
        get_config=get_config,
        get_default_config_path=get_default_config_path,
        deploy_configuration=deploy_configuration,
        display_config=display_config,
        init_logging=init_logging,
        check_logging_config=check_logging_config,
        machine_sources=machine_sources,
    )


def build_testing(*, sources: MachineSources | None = None) -> AppServices:
    """Wire in-memory adapters into an AppServices container.

    Args:
        sources: the machine collect and check read; None gives a machine that answers
            nothing (every question records an error).

    Returns:
        AppServices container with in-memory adapters.
    """
    from ..adapters.fixture import FixtureSources  # noqa: PLC0415 - deferred: keeps test doubles out of the production import path
    from ..adapters.memory import (  # noqa: PLC0415 - deferred: keeps in-memory test doubles out of the production import path
        check_logging_config_in_memory,
        deploy_configuration_in_memory,
        display_config_in_memory,
        get_config_in_memory,
        get_default_config_path_in_memory,
        init_logging_in_memory,
    )

    if sources is None:
        empty = FixtureSources({})
        sources = WindowsSources(platform=empty, registry=empty, cpuid=empty)
    machine = sources
    return AppServices(
        get_config=get_config_in_memory,
        get_default_config_path=get_default_config_path_in_memory,
        deploy_configuration=deploy_configuration_in_memory,
        display_config=display_config_in_memory,
        init_logging=init_logging_in_memory,
        check_logging_config=check_logging_config_in_memory,
        machine_sources=lambda: machine,
    )


__all__ = [
    "AppServices",
    "build_production",
    "build_testing",
    "check_logging_config",
    "deploy_configuration",
    "display_config",
    "get_config",
    "get_default_config_path",
    "init_logging",
    "machine_sources",
]

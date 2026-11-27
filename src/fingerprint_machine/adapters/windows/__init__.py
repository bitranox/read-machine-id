"""Windows adapters: CIM through pwshpy, firmware tables, TBS, device properties and kernel queries
through ctypes, the registry through lib_registry.

Contents:
    * :mod:`.platform` - :class:`PwshpyPlatformSource`.
    * :mod:`.firmware` - the ctypes calls into kernel32 and tbs.
    * :mod:`.devnode` - device properties from cfgmgr32.
    * :mod:`.kernel` - the NUMA topology and the DMA guard policy.
    * :mod:`.registry` - :class:`LibRegistrySource`.
"""

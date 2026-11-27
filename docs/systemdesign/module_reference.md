# Module Reference: Architecture & File Index

## Status

Describes the modules as they are in the source tree. Update it with every change that adds,
moves or removes a module, a CLI option or a public name.

---

## Related Files

### Domain Layer
- `src/read_machine_id/domain/enums.py`  -  Type-safe enums (OutputFormat, DeployTarget)
- `src/read_machine_id/domain/errors.py`  -  Domain exceptions (ConfigurationError)

### Application Layer
- `src/read_machine_id/application/ports.py`  -  Callable Protocol definitions for adapter functions

### Adapters Layer
- `src/read_machine_id/adapters/config/loader.py`  -  Configuration loading with LRU caching
- `src/read_machine_id/adapters/config/deploy.py`  -  Configuration deployment
- `src/read_machine_id/adapters/config/display.py`  -  Configuration display (TOML/JSON output, redaction)
- `src/read_machine_id/adapters/config/overrides.py`  -  CLI `--set` override parsing and deep-merge
- `src/read_machine_id/adapters/logging/setup.py`  -  lib_log_rich initialization; takes only the `LOG_*` lines of a `.env`, and raises `InvalidLoggingConfigError` for a refused `[lib_log_rich]` value or `LOG_*` variable, after starting logging with its defaults (and without the `LOG_*` variables only when one of them is refused); `check_logging_config` refuses another configuration's logging settings through lib_log_rich's `validate_config`, without touching the running runtime; `run_logdemo` runs lib_log_rich's demo and raises `InvalidLoggingConfigError` for a `LOG_*` variable the demo refuses
- `src/read_machine_id/adapters/cli/`  -  CLI adapter package:
  - `__init__.py`  -  Public facade
  - `constants.py`  -  Shared constants
  - `safe_console.py`  -  Encode-safe terminal output; use `safe_console.echo` instead of `click.echo`
  - `exit_codes.py`  -  POSIX exit codes (ExitCode IntEnum)
  - `context.py`  -  Click context helpers (`CLIContext`) and the traceback preference state
  - `config_load.py`  -  Configuration load for the CLI; records a load failure, `require_config` refuses with exit 78, `check_logging` checks the logging settings of a configuration reloaded by `config --profile`, refusing them as the root does
  - `root.py`  -  Root command group
  - `main.py`  -  Entry point
  - `typed_click.py`  -  Strictly typed wrappers for rich_click's `option`, `version_option` and `get_current_context`
  - `commands/info.py`  -  info, fail commands
  - `commands/config.py`  -  config, config-deploy, config-generate-examples commands
  - `commands/logging.py`  -  logdemo command

### Adapters Layer (In-Memory / Testing)
- `src/read_machine_id/adapters/memory/__init__.py`  -  Public facade + Protocol conformance assertions
- `src/read_machine_id/adapters/memory/config.py`  -  In-memory config adapters
- `src/read_machine_id/adapters/memory/logging.py`  -  In-memory logging (a quiet lib_log_rich runtime for tests)

### Composition Layer
- `src/read_machine_id/composition/__init__.py`  -  Wires adapters to ports

### Entry Points
- `src/read_machine_id/entry.py`  -  Console-script entry point; wires production services before invoking the CLI
- `src/read_machine_id/__main__.py`  -  Thin shim for `python -m`
- `src/read_machine_id/__init__.py`  -  Public API exports
- `src/read_machine_id/__init__conf__.py`  -  Package metadata constants

### Configuration Defaults
- `src/read_machine_id/adapters/config/defaultconfig.toml`  -  Base defaults
- `src/read_machine_id/adapters/config/defaultconfig.d/40-layered-config.toml`  -  lib_layered_config integration docs
- `src/read_machine_id/adapters/config/defaultconfig.d/90-logging.toml`  -  Logging defaults

### Tests
- `conftest.py` (repository root)  -  The two configuration-layer redirects; at the root so they also reach the doctests `--doctest-modules` collects from `src/`
- `tests/conftest.py`  -  Shared fixtures (see Test Fixtures below)
- `tests/layer_roots.py`  -  The environment variables that place each configuration layer, shared by both conftests and the subprocess tests
- `tests/test_cache_effectiveness.py`  -  Configuration loading returns consistent (cached) results
- `tests/test_cli_config.py`  -  `config`, `config-deploy`, `config-generate-examples` commands
- `tests/test_cli_config_errors.py`  -  A configuration that cannot be loaded: who reports it, and who still runs
- `tests/test_cli_core.py`  -  Traceback, main entry, help, fail, info, unknown command
- `tests/test_cli_env_file.py`  -  `--env-file` path passing, validation and value override
- `tests/test_cli_exit_codes.py`  -  Exit codes through the CLI
- `tests/test_cli_main_exit.py`  -  Exit codes and stderr through the real `main()` entry point
- `tests/test_cli_overrides.py`  -  `--set` through the CLI
- `tests/test_cli_validation.py`  -  Profile name validation
- `tests/test_config_overrides.py`  -  `--set` parsing tests
- `tests/test_declared_dependencies.py`  -  Every third-party module imported at run time is a declared dependency
- `tests/test_deploy_mode_safety.py`  -  `--dir-mode`/`--file-mode` literal, range and safety checks
- `tests/test_deploy_permissions.py`  -  `config-deploy` permission options
- `tests/test_display.py`  -  Config display formatting tests
- `tests/test_enums.py`  -  Domain enum tests
- `tests/test_errors.py`  -  Domain error types
- `tests/test_logging.py`  -  Logging configuration model
- `tests/test_logging_dotenv_isolation.py`  -  Only `LOG_*` lines of a `.env` reach the environment; an invalid `[lib_log_rich]` section or `LOG_*` variable is a configuration failure that leaves logging running
- `tests/test_memory_logging.py`  -  Testing-composition logging runtime and the per-test logging reset
- `tests/test_metadata.py`  -  Package metadata and PEP 561 marker tests
- `tests/test_metadata_sync.py`  -  `__init__conf__` constants stay in sync with `pyproject.toml`
- `tests/test_module_entry.py`  -  `python -m` entry tests
- `tests/test_permission_defaults.py`  -  `config-deploy` hands permissions to lib_layered_config: `--set` overrides, `.env` and deployed destinations never decide a mode, refusals exit 78
- `tests/test_ports.py`  -  Protocol conformance tests
- `tests/test_property_overrides.py`  -  Property-based `--set` override tests
- `tests/test_safe_console.py`  -  Legacy-codepage output tests, plus the guard forbidding direct `click.echo`

---

## Architecture

### Layer Assignments

| Directory/Module       | Layer       | Responsibility                                |
|------------------------|-------------|-----------------------------------------------|
| `domain/`              | Domain      | Pure logic  -  no I/O, logging, or frameworks |
| `application/ports.py` | Application | Protocol definitions for adapters             |
| `adapters/config/`     | Adapters    | Configuration loading, deployment, display    |
| `adapters/logging/`    | Adapters    | lib_log_rich initialization                   |
| `adapters/cli/`        | Adapters    | Click CLI framework integration               |
| `adapters/memory/`     | Adapters    | In-memory implementations for testing         |
| `composition/`         | Composition | Wires adapters to ports                       |

### Import Enforcement

Layer boundaries enforced via `import-linter` contracts in `pyproject.toml`:
- **Domain is pure**: Cannot import from adapters or composition
- **Clean Architecture layers**: Validates dependency direction (composition -> adapters -> application -> domain)

Run `lint-imports` to verify compliance.

---

## Exit Codes

POSIX-conventional exit codes defined in `adapters/cli/exit_codes.py`:

| Code | Name                | Usage                                                                                                    |
|------|---------------------|----------------------------------------------------------------------------------------------------------|
| 0    | `SUCCESS`           | Command completed successfully                                                                           |
| 1    | `GENERAL_ERROR`     | Unhandled exception, general failure                                                                     |
| 2    | `FILE_NOT_FOUND`    | File not found; also click's usage error (bad option value, malformed `--set`, invalid `--profile` name) |
| 13   | `PERMISSION_DENIED` | Cannot write to target directory                                                                         |
| 22   | `INVALID_ARGUMENT`  | Invalid CLI argument or section not found                                                                |
| 78   | `CONFIG_ERROR`      | Configuration missing, not loadable or invalid                                                           |
| 110  | `TIMEOUT`           | Operation timed out                                                                                      |
| 130  | `SIGNAL_INT`        | Interrupted (SIGINT/Ctrl+C)                                                                              |
| 141  | `BROKEN_PIPE`       | Output pipe closed                                                                                       |
| 143  | `SIGNAL_TERM`       | Terminated (SIGTERM)                                                                                     |

---

## CLI Commands

### Root Command

**Command:** `read-machine-id`

| Option                         | Description                                 |
|--------------------------------|---------------------------------------------|
| `--version`                    | Show version and exit                       |
| `--traceback / --no-traceback` | Show full Python traceback on errors        |
| `--profile NAME`               | Load configuration from a named profile     |
| `--set SECTION.KEY=VALUE`      | Override configuration setting (repeatable) |
| `--env-file PATH`              | Explicit `.env` file path                   |
| `-h, --help`                   | Show help and exit                          |

### info

Print resolved package metadata.

**Exit codes:** 0

### fail

Trigger intentional `RuntimeError` for testing error handling.

**Exit codes:** 1

### config

Display merged configuration from all sources.

| Option                   | Description                    |
|--------------------------|--------------------------------|
| `--format [human\|json]` | Output format (default: human) |
| `--section NAME`         | Show only specific section     |
| `--profile NAME`         | Override the root's profile    |

**Exit codes:** 0, 2 (usage error), 22 (section not found), 78 (configuration not loadable)

### config-deploy

Deploy default configuration to system or user directories.

| Option                             | Description                                                      |
|------------------------------------|------------------------------------------------------------------|
| `--target [app\|host\|user]`       | Target layer(s)  -  required, repeatable                         |
| `--force`                          | Replace differing files, keeping the old one as `<name>.bak`     |
| `--profile NAME`                   | Deploy to profile subdirectory                                   |
| `--permissions / --no-permissions` | Set Unix permissions (default: `enabled` from the configuration) |
| `--dir-mode MODE`                  | Directory mode for every target (octal)                          |
| `--file-mode MODE`                 | File mode for every target (octal)                               |

**Exit codes:** 0, 1, 2 (usage error, including a refused `--dir-mode`/`--file-mode` or `--profile` name, and `--no-permissions` together with a mode), 13 (permission denied), 78 (lib_layered_config refused the permission settings: a configured one, which both `--dir-mode` and `--file-mode` or `--no-permissions` deploy past, or a `--set` of `lib_layered_config.default_permissions`)

### config-generate-examples

Generate example configuration files.

| Option              | Description                   |
|---------------------|-------------------------------|
| `--destination DIR` | Target directory  -  required |
| `--force`           | Overwrite existing files      |

**Exit codes:** 0, 1

### logdemo

Run logging demonstration.

| Option         | Description                                                                                                        |
|----------------|--------------------------------------------------------------------------------------------------------------------|
| `--theme NAME` | Logging theme: one of lib_log_rich's `ConsoleTheme` values, `classic`, `dark`, `neon`, `pastel` (default: classic) |

The demo runs lib_log_rich's own demo runtime: it does not read the configuration, so a
`--set lib_log_rich.*` value changes nothing in it, while a `LOG_*` variable does.

**Exit codes:** 0, 2 (an unknown `--theme`), 78 (a `LOG_*` variable lib_log_rich refuses, with lib_log_rich's own line, as `config` writes it)

---

## Profile Validation

Profile names (`--profile` option) are validated using `lib_layered_config.validate_profile_name()`.

### validate_profile()

**Location:** `adapters/config/loader.py`

```python
def validate_profile(profile: str, max_length: int | None = None) -> None:
    """Validate profile name using lib_layered_config."""
```

| Parameter    | Type          | Default  | Description                                 |
|--------------|---------------|----------|---------------------------------------------|
| `profile`    | `str`         | required | Profile name to validate                    |
| `max_length` | `int \| None` | 64       | Maximum length (DEFAULT_MAX_PROFILE_LENGTH) |

### Validation Rules

| Rule             | Description                                          |
|------------------|------------------------------------------------------|
| Maximum length   | 64 characters (configurable via `max_length`)        |
| Character set    | ASCII alphanumeric, hyphens (`-`), underscores (`_`) |
| Start character  | Must start with alphanumeric character               |
| Empty string     | Rejected                                             |
| Windows reserved | CON, PRN, AUX, NUL, COM1-9, LPT1-9 rejected          |
| Path traversal   | `/`, `\`, `..` rejected                              |
| Control chars    | Rejected                                             |

### Error Handling

Raises `ValueError` with descriptive message on invalid input.

---

## Configuration Overrides

`adapters/config/overrides.py` parses and applies `--set SECTION.KEY=VALUE`. Public names
(`__all__`):

| Name              | Kind     | Purpose                                                                                 |
|-------------------|----------|-----------------------------------------------------------------------------------------|
| `parse_override`  | function | Split one `SECTION.KEY[.SUBKEY...]=VALUE` string into a `ConfigOverride`                |
| `coerce_value`    | function | Read a raw value as JSON (bool, number, null, array, object), falling back to the text  |
| `nest_overrides`  | function | Parse all `--set` values into the nested mapping they override, refusing contradictions |
| `apply_overrides` | function | Deep-merge the overrides into a `Config`, recording their provenance as `CLI_LAYER`     |
| `ConfigOverride`  | class    | One parsed override: section, key path and value                                        |
| `CoercedValue`    | type     | Union of the types `coerce_value` can return                                            |
| `CLI_LAYER`       | constant | Provenance layer name (`"cli"`) for a value that came from `--set`                      |

---

## Testing Infrastructure

### In-Memory Adapters

The `adapters/memory/` package provides lightweight implementations for testing:

| Module              | Protocols Satisfied                                                         |
|---------------------|-----------------------------------------------------------------------------|
| `memory/config.py`  | `GetConfig`, `GetDefaultConfigPath`, `DeployConfiguration`, `DisplayConfig` |
| `memory/logging.py` | `InitLogging`, `CheckLoggingConfig`                                         |

Use `composition.build_testing()` to wire all in-memory adapters.

### Test Fixtures (conftest.py)

`system_layers_in_tmp_path` and `user_layer_in_tmp_path` live in the rootdir `conftest.py`; the rest in
`tests/conftest.py`.

| Fixture                     | Purpose                                                                                                                                                                                                                                                   |
|-----------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `config_factory`            | Creates real `Config` instances from test data                                                                                                                                                                                                            |
| `inject_config`             | Injects config into CLI path                                                                                                                                                                                                                              |
| `cli_runner`                | Fresh `CliRunner` per test                                                                                                                                                                                                                                |
| `strip_ansi`                | Strips ANSI escape codes from output                                                                                                                                                                                                                      |
| `clear_config_cache`        | Clears LRU cache before tests                                                                                                                                                                                                                             |
| `managed_traceback_state`   | Resets/restores traceback configuration                                                                                                                                                                                                                   |
| `isolated_logging_state`    | Autouse: after every test, shuts the lib_log_rich runtime down and restores the root logger; yields that restore step                                                                                                                                     |
| `system_layers_in_tmp_path` | Autouse: points the app and host layers (`LIB_LAYERED_CONFIG_ETC`, `_MAC_APP_ROOT`, `_PROGRAMDATA`) at an empty directory under `tmp_path` and returns it                                                                                                 |
| `user_layer_in_tmp_path`    | Autouse: points the user layer (`XDG_CONFIG_HOME`, `LIB_LAYERED_CONFIG_MAC_HOME_ROOT`, `_APPDATA`, `_LOCALAPPDATA`) at an empty directory under `tmp_path` and returns it, so a real deploy writes there; `HOME` is left alone because git and uv read it |
| `app_layer_config_file`     | The app layer's `config.toml` path under the redirect, its directory created                                                                                                                                                                              |
| `user_layer_config_file`    | The user layer's `config.toml` path under the redirect, its directory created                                                                                                                                                                             |

---

**Last Updated:** 2026-11-27 (email feature and hello command removed)

# read_machine_id

<!-- Badges -->
[![CI](https://github.com/bitranox/read_machine_id/actions/workflows/default_cicd_public.yml/badge.svg)](https://github.com/bitranox/read_machine_id/actions/workflows/default_cicd_public.yml)
[![CodeQL](https://github.com/bitranox/read_machine_id/actions/workflows/codeql.yml/badge.svg)](https://github.com/bitranox/read_machine_id/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Open in Codespaces](https://img.shields.io/badge/Codespaces-Open-blue?logo=github&logoColor=white&style=flat-square)](https://codespaces.new/bitranox/read_machine_id?quickstart=1)
[![PyPI](https://img.shields.io/pypi/v/read_machine_id.svg)](https://pypi.org/project/read_machine_id/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/read_machine_id.svg)](https://pypi.org/project/read_machine_id/)
[![Code Style: Ruff](https://img.shields.io/badge/Code%20Style-Ruff-46A3FF?logo=ruff&labelColor=000)](https://docs.astral.sh/ruff/)
[![codecov](https://codecov.io/gh/bitranox/read_machine_id/graph/badge.svg?token=UFBaUDIgRk)](https://codecov.io/gh/bitranox/read_machine_id)
[![Maintainability](https://qlty.sh/badges/041ba2c1-37d6-40bb-85a0-ec5a8a0aca0c/maintainability.svg)](https://qlty.sh/gh/bitranox/projects/read_machine_id)
[![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)


`read_machine_id` is a template CLI application demonstrating configuration management and structured logging. It showcases rich-click for ergonomics and lib_cli_exit_tools for exits, providing a solid foundation for building CLI applications.
- CLI entry point styled with rich-click (rich output + click ergonomics).
- Layered configuration system with lib_layered_config (defaults -> app -> host -> user -> .env -> env).
  The `.env` is the first one found from the current directory upward; when there is none,
  `$XDG_CONFIG_HOME/read-machine-id/.env` (`~/.config/...` when unset) is read on Linux
  (see [CONFIG.md](CONFIG.md) for macOS and Windows).
- Rich structured logging with lib_log_rich (console, journald, eventlog, Graylog/GELF).
- Exit-code and messaging helpers powered by lib_cli_exit_tools.
- Metadata helpers ready for packaging, testing, and release automation.


### Python 3.10+ Baseline

- The project targets **Python 3.10 and newer**.
- Runtime dependencies are declared with >= floors in pyproject.toml. Dev
  dependencies (pytest, ruff, pyright, bandit, etc.) are declared the same way.
- CI workflows exercise GitHub's rolling runner images (`ubuntu-latest`,
  `macos-latest`, `windows-latest`) and cover CPython 3.10 through 3.15
  alongside the latest available 3.x release provided by Actions.

---

## Install - recommended via uv

[uv](https://docs.astral.sh/uv/) is an ultrafast Python package manager written in Rust (10-20x faster than pip/poetry).

### Install uv (if not already installed) 
```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Copy the actual binaries
cp /root/.local/bin/uv /usr/local/bin/uv
cp /root/.local/bin/uvx /usr/local/bin/uvx

# Ensure world-executable
chmod 755 /usr/local/bin/uv /usr/local/bin/uvx

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### One-shot run (no install needed)

```bash
uvx read-machine-id@latest --help
```

### Persistent install as CLI tool

```bash
# One-time install from PyPI (isolated environment, added to PATH)
uv tool install read-machine-id
# or from the git repository
uv tool install --from "git+https://github.com/bitranox/read_machine_id.git" read-machine-id
# Pick the interpreter explicitly if needed, e.g. --python 3.14
# Update (requires network)
uv tool upgrade read-machine-id
# Run
read-machine-id --help
```

### Install as project dependency

```bash
uv venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
uv pip install read-machine-id
```

For alternative install paths (pip, pipx, source builds, etc.), see
[INSTALL.md](INSTALL.md). All supported methods register both the
`read_machine_id` and `read-machine-id` commands on your PATH.

### Why we recommend uv: supply-chain protection

This repository commits a `uv.lock`. It pins every package the project needs, transitive
dependencies included, to an exact version and to the hashes of that version's files. The
`exclude-newer` setting under `[tool.uv]` in `pyproject.toml` adds a cooldown: uv leaves any
release younger than that out of the lock. CI installs from the lock, so a hijacked release that
gets pulled again within the cooldown never reaches our builds, and a file whose hash does not
match is refused.

That protection stays in this repository. The installable package declares only lower bounds
(`>=`) for its dependencies, so a plain `pip install` takes the newest release of every transitive
dependency at the moment you run it. If one of them was hijacked an hour earlier, you get the
hijacked version. `pipx install` and `uv tool install` without options do the same.

To install the command line tool with a cooldown of your own (uv then skips any release younger
than 7 days, transitive ones included), or to run the exact tree our CI tests:

```bash
uv tool install --exclude-newer "7 days" read_machine_id
git clone https://github.com/bitranox/read_machine_id.git && cd read_machine_id && uv sync --locked && uv run read_machine_id --help
```

If you depend on read_machine_id in your own project, give that project the same cooldown (7 days here, as
an example) and commit the `uv.lock` that `uv add read_machine_id` writes:

```toml
[tool.uv]
exclude-newer = "7 days"
```

---

## Configuration

See [CONFIG.md](CONFIG.md) for detailed documentation on the layered configuration system, including precedence rules, profile support, and customization best practices.

---

## Quick Start

```bash
# Install
uv tool install read-machine-id

# Verify
read-machine-id --version

# deploy config files (user level; --target app or host needs sudo)
read-machine-id config-deploy --target user

# Try it out
read-machine-id info
read-machine-id config
```

---

## Usage

The CLI leverages [rich-click](https://github.com/ewels/rich-click) so help output, validation errors, and prompts render with Rich styling while keeping the familiar click ergonomics.

### Available Commands

```bash
# Display package information
read-machine-id info

# Error-handling demo
read-machine-id fail
read-machine-id --traceback fail

# Configuration management
read-machine-id config                         # Show current configuration
read-machine-id config --format json           # Show as JSON
read-machine-id config --section lib_log_rich  # Show specific section
read-machine-id config --profile production    # Use a named profile

# Deploy configuration templates to target directories
# Without profile:
read-machine-id config-deploy --target app    # -> /etc/xdg/{slug}/config.toml
read-machine-id config-deploy --target host   # -> /etc/xdg/{slug}/hosts/{hostname}.toml
read-machine-id config-deploy --target user   # -> ~/.config/{slug}/config.toml

# With profile:
read-machine-id config-deploy --target app --profile production   # -> /etc/xdg/{slug}/profile/production/config.toml
read-machine-id config-deploy --target host --profile production  # -> /etc/xdg/{slug}/profile/production/hosts/{hostname}.toml
read-machine-id config-deploy --target user --profile production  # -> ~/.config/{slug}/profile/production/config.toml

# With custom permissions (POSIX only):
read-machine-id config-deploy --target user --file-mode 640       # Files with rw-r----- (640)
read-machine-id config-deploy --target user --dir-mode 750        # Directories with rwxr-x--- (750)
read-machine-id config-deploy --target app --no-permissions       # Skip permission setting (use umask)

# Profile names: alphanumeric, hyphens, underscores; max 64 chars; must start with letter/digit
# See CONFIG.md for full validation rules

# Deploy configuration examples
read-machine-id config-generate-examples --destination ./examples

# Load configuration from an explicit .env file (skips upward directory search)
read-machine-id --env-file /path/to/.env config

# Override configuration at runtime (repeatable --set)
read-machine-id --set lib_log_rich.console_level=DEBUG config

# Logging demo
read-machine-id logdemo
LOG_CONSOLE_LEVEL=DEBUG read-machine-id logdemo   # logdemo reads LOG_* only, not --set

# All commands work with any entry point
python -m read_machine_id info
uvx read-machine-id info
```

---

## Further Documentation

- [Install Guide](INSTALL.md)
- [Development Handbook](DEVELOPMENT.md)
- [Contributor Guide](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Module Reference](docs/systemdesign/module_reference.md)
- [License](LICENSE)

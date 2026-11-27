# AI transparency

The author and owner of this project is the human, [@bitranox](https://github.com/bitranox).
Every design and engineering decision is theirs, and they answer for everything published here.
An AI assistant (Claude, run through the Claude Code CLI) was used as a tool along the way,
mostly for the typing and the legwork under that direction. This page says where, plainly, so
you can weigh the work on its merits. The reasoning behind working this way is in
[ai-stance.md](ai-stance.md).

## The human's work

- The problem is theirs: moving Windows machines between hardware and hypervisors changes
  identity values (system UUID, serials, MAC addresses, NIC slot numbers, disk ids, the Windows
  device id) that licensing, activation and driver bindings depend on, and there was no single
  tool that reads them all and says what changed.
- The scope is theirs: everything a machine says about itself, including SMBIOS, adapter
  numbers, serials, network card settings, the Windows ids, product id and TPM state; a standalone
  tool that prints JSON and can save it to a file; a public repository, not tied to any one
  hypervisor.
- So are the structural choices: building on the bitranox CLI template and its layering, reading
  WMI through `pwshpy` and the registry through `lib_registry` (which falls back to `fake_winreg`
  off Windows, so the registry code runs for real in the tests), and comparing readings field by
  field with changing counters left out of the score.
- The human reviewed and corrected the work at each step; what ships is what they signed off on.
- Every commit went out under the human's name and authority, with no AI co-author line. The
  human is responsible for what is published.

## Where the AI was used

As a tool, under the human's direction, it did the mechanical parts: typing the SMBIOS decoders,
the readers, the CLI commands, the tests and the docs to the human's design; building synthetic
test machines so no real serial or key appears in the repository; running the tool on a real
Windows machine and fixing what that run showed; and checking the prose against the code so the
docs describe what the code does now. None of the decisions, and none of the accountability, were
the AI's.

## What's been checked

The gate is `make test`, and CI runs the same checks: Ruff (lint and format), Pyright in strict
mode, the import-linter layer contracts, Bandit, pip-audit, and Pytest with coverage, including
the doctests in the source modules. The tests replay a recorded synthetic machine through the real
CLI, and one test reads the CI's own Windows runner for real. A planted product key proves that no
full key reaches the output. CI runs on Linux and Windows under
Python 3.15. The badges at the top of the README report the live state.

## Checking it yourself

You do not have to take any of this on faith.

- The source is available. Read `src/fingerprint_machine/`; the module-by-module map is in
  [docs/systemdesign/module_reference.md](docs/systemdesign/module_reference.md).
- The history is available too. Decisions and reversals show up over time.
- The tests live in `tests/` and the doctests live in the modules. Run `make test` and see.

If something does not line up, open an issue. That is what they are for.

## License and attribution

The text and code here are under the MIT License (see [LICENSE](LICENSE)). Anthropic's terms put
ownership of model output with the user, so the human owns this and answers for it.

# GitHub Copilot Instructions — win-sentinel

Canonical rules: **[AGENTS.md](../AGENTS.md)** (shared with Claude).

Essentials (full detail in AGENTS.md):
- **Python only** — no PowerShell/batch/VBScript in the app: psutil, pywin32 (`wmi.query`, `wmi.dispatch`), ctypes, winreg, stdlib. COM per thread, late-bound, never shared across threads.
- **Jobs** — `fn(ctx) -> result`; honor `ctx.check()`; scheduled runs use saved settings, save the report, email per policy.
- **Security** — collectors in `security.py`, decisions in pure `rules.py`; stable finding keys (trust list).
- **GUI** — PySide6 on the main thread, one job at a time in a daemon thread, events via `queue.SimpleQueue` + `QTimer`. No `qasync`. Tray app, single instance, runs elevated.
- **Updates** — ask first; install only a SHA-256-verified installer; `--smoke-test` must pass.
- **Style** — PEP 8, 100-char lines, `ruff` lint + format authoritative, `mypy --strict` (win32).
- **Tests** — `python -m pytest`; Windows APIs mocked; `tests/test_windows.py` hits the real APIs on Windows CI.
- **Release** — Conventional Commits + `release-please` (GitHub release + Windows installer + .sha256).
- **Be terse** — minimal prose; report file paths + pass/fail.

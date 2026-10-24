import re
from pathlib import Path

import winsentinel
from winsentinel.__main__ import main

ROOT = Path(__file__).resolve().parent.parent


def test_version_matches_pyproject_and_release_manifest():
    match = re.search(
        r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.MULTILINE
    )
    assert match is not None
    assert winsentinel.__version__ == match.group(1)
    assert f'"{winsentinel.__version__}"' in (ROOT / ".release-please-manifest.json").read_text()


def test_cli_version_flag(capsys):
    try:
        main(["--version"])
    except SystemExit as e:
        assert e.code == 0
    assert winsentinel.__version__ in capsys.readouterr().out


def test_the_app_never_runs_powershell():
    for path in (ROOT / "winsentinel").rglob("*.py"):
        text = path.read_text(encoding="utf-8").lower()
        assert "powershell.exe" not in text, path
        assert "encodedcommand" not in text or path.name == "indicators.py", path

"""Self-update from GitHub Releases.

``latest_release()`` reads the newest release; when it is newer, the GUI asks first,
then ``download()`` fetches the Windows installer and checks its SHA-256 against the
digest GitHub publishes for the asset (or the ``.sha256`` file attached next to it).
A file that doesn't match is deleted, never run. ``launch_installer()`` starts the
installer silently; it closes this app, replaces the files and starts it again.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from winsentinel import APP_NAME, REPO, __version__, paths, winapi
from winsentinel.report import Cancelled

logger = logging.getLogger(__name__)

RELEASES_API = f"https://api.github.com/repos/{REPO}/releases/latest"
INSTALLER_NAME = re.compile(rf"^{APP_NAME}-[\d.]+-windows-setup\.exe$")
_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
CHUNK = 64 * 1024

_urlopen: Callable[..., Any] = urllib.request.urlopen


class UpdateError(RuntimeError):
    """The update could not be downloaded or failed verification."""


@dataclass(frozen=True)
class Release:
    version: str
    page_url: str
    notes: str = ""
    installer_name: str = ""
    installer_url: str = ""
    size: int = 0
    sha256: str = ""
    checksum_url: str = ""

    @property
    def installable(self) -> bool:
        return bool(self.installer_url and (self.sha256 or self.checksum_url))


def parse_version(v: str) -> tuple[int, ...]:
    """'v1.2.3' or '1.2.3' -> (1, 2, 3); (0,) when unparseable."""
    try:
        return tuple(int(x) for x in v.strip().lstrip("v").split("."))
    except ValueError:
        return (0,)


def is_newer(release: Release, current: str = __version__) -> bool:
    return parse_version(release.version) > parse_version(current)


def parse_release(data: dict[str, Any]) -> Release | None:
    tag = str(data.get("tag_name") or "").lstrip("v")
    page = str(data.get("html_url") or "")
    if not tag or not page or data.get("draft") or data.get("prerelease"):
        return None
    assets = [a for a in data.get("assets") or [] if isinstance(a, dict)]
    installer = next((a for a in assets if INSTALLER_NAME.match(str(a.get("name")))), None)
    if installer is None:
        return Release(tag, page, str(data.get("body") or ""))
    name = str(installer["name"])
    digest = str(installer.get("digest") or "")
    checksum = next((a for a in assets if a.get("name") == f"{name}.sha256"), None)
    return Release(
        version=tag,
        page_url=page,
        notes=str(data.get("body") or ""),
        installer_name=name,
        installer_url=str(installer.get("browser_download_url") or ""),
        size=int(installer.get("size") or 0),
        sha256=digest.split(":", 1)[1].lower() if digest.startswith("sha256:") else "",
        checksum_url=str(checksum.get("browser_download_url") or "") if checksum else "",
    )


def _request(url: str, accept: str) -> urllib.request.Request:
    return urllib.request.Request(
        url, headers={"Accept": accept, "User-Agent": f"{APP_NAME}/{__version__}"}
    )


def latest_release(timeout: float = 10) -> Release | None:
    """The newest published release, or None. Raises OSError / ValueError on failure."""
    with _urlopen(_request(RELEASES_API, "application/vnd.github+json"), timeout=timeout) as resp:
        data = json.loads(resp.read())
    return parse_release(data) if isinstance(data, dict) else None


def expected_sha256(release: Release, timeout: float = 30) -> str:
    if release.sha256:
        return release.sha256
    if not release.checksum_url:
        raise UpdateError("the release publishes no checksum for its installer")
    with _urlopen(
        _request(release.checksum_url, "application/octet-stream"), timeout=timeout
    ) as resp:
        text = resp.read(4096).decode("ascii", "replace")
    m = _SHA256.search(text)
    if not m:
        raise UpdateError("unreadable checksum file")
    return m.group(0).lower()


def download(
    release: Release,
    on_progress: Callable[[int, int], None] | None = None,
    stop: threading.Event | None = None,
    dest: Path | None = None,
    timeout: float = 30,
) -> Path:
    """Download and verify the installer; returns its path. Raises UpdateError,
    Cancelled (stop set) or OSError."""
    if not release.installer_url:
        raise UpdateError("the release has no Windows installer")
    expected = expected_sha256(release, timeout)
    folder = dest or paths.updates_dir()
    folder.mkdir(parents=True, exist_ok=True)
    final = folder / release.installer_name
    part = final.with_name(final.name + ".part")
    digest = hashlib.sha256()
    done = 0
    try:
        with _urlopen(
            _request(release.installer_url, "application/octet-stream"), timeout=timeout
        ) as resp:
            total = int(resp.headers.get("Content-Length") or release.size or 0)
            with part.open("wb") as out:
                while chunk := resp.read(CHUNK):
                    if stop is not None and stop.is_set():
                        raise Cancelled
                    out.write(chunk)
                    digest.update(chunk)
                    done += len(chunk)
                    if on_progress is not None:
                        on_progress(done, total)
        actual = digest.hexdigest()
        if actual != expected:
            raise UpdateError(
                f"checksum mismatch (expected {expected[:12]}..., got {actual[:12]}...)"
            )
        part.replace(final)
    finally:
        part.unlink(missing_ok=True)
    logger.info("Downloaded %s (%d bytes, SHA-256 verified)", final.name, done)
    return final


def install_command(installer: Path) -> list[str]:
    log = paths.updates_dir() / "install.log"
    return [
        str(installer),
        "/SILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/CLOSEAPPLICATIONS",
        "/RELAUNCH=1",
        f"/LOG={log}",
    ]


def launch_installer(installer: Path) -> None:
    """Start the installer detached; the caller should quit right after."""
    logger.info("Starting the installer: %s", installer.name)
    winapi.spawn_detached(install_command(installer))


def clean_downloads(keep: Path | None = None) -> None:
    for old in paths.updates_dir().glob(f"{APP_NAME}-*-windows-setup.exe*"):
        if keep is None or old != keep:
            old.unlink(missing_ok=True)

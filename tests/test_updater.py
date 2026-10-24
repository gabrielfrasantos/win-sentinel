import hashlib
import io
import json
import threading

import pytest

from winsentinel import updater
from winsentinel.report import Cancelled

PAYLOAD = b"MZ fake installer" * 1000
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
NAME = "win-sentinel-0.2.0-windows-setup.exe"


def release_json(**asset_extra):
    asset = {
        "name": NAME,
        "browser_download_url": f"https://example.invalid/{NAME}",
        "size": len(PAYLOAD),
        **asset_extra,
    }
    return {
        "tag_name": "v0.2.0",
        "html_url": "https://github.com/gabrielfrasantos/win-sentinel/releases/tag/v0.2.0",
        "body": "## Features\n* things",
        "assets": [
            asset,
            {"name": f"{NAME}.sha256", "browser_download_url": "https://example.invalid/sum"},
        ],
    }


class Response(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.headers = {"Content-Length": str(len(data))}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def web(monkeypatch):
    pages = {}

    def urlopen(request, timeout=None):
        return Response(pages[request.full_url])

    monkeypatch.setattr(updater, "_urlopen", urlopen)
    return pages


def test_parse_release_with_github_digest():
    r = updater.parse_release(release_json(digest=f"sha256:{DIGEST.upper()}"))
    assert (r.version, r.installer_name, r.sha256, r.installable) == ("0.2.0", NAME, DIGEST, True)
    assert updater.is_newer(r, "0.1.9") and not updater.is_newer(r, "0.2.0")
    assert updater.parse_release({**release_json(), "draft": True}) is None
    assert not updater.parse_release({**release_json(), "assets": []}).installable


def test_parse_version():
    assert updater.parse_version("v1.10.2") == (1, 10, 2)
    assert updater.parse_version("1.2.3-beta") == (0,)


def test_latest_release(web):
    web[updater.RELEASES_API] = json.dumps(release_json()).encode()
    r = updater.latest_release()
    assert r.version == "0.2.0" and r.checksum_url == "https://example.invalid/sum"


def test_download_verifies_with_checksum_file(web, tmp_path):
    r = updater.parse_release(release_json())
    web[r.installer_url] = PAYLOAD
    web[r.checksum_url] = f"{DIGEST}  {NAME}\n".encode()
    progress = []
    path = updater.download(r, lambda d, t: progress.append((d, t)), dest=tmp_path)
    assert path.read_bytes() == PAYLOAD and path.name == NAME
    assert progress[-1] == (len(PAYLOAD), len(PAYLOAD))
    assert not list(tmp_path.glob("*.part"))


def test_download_rejects_a_tampered_file(web, tmp_path):
    r = updater.parse_release(release_json(digest="sha256:" + "0" * 64))
    web[r.installer_url] = PAYLOAD
    with pytest.raises(updater.UpdateError, match="checksum mismatch"):
        updater.download(r, dest=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_download_without_checksum_is_refused(web, tmp_path):
    data = release_json()
    data["assets"] = data["assets"][:1]
    r = updater.parse_release(data)
    assert not r.installable
    with pytest.raises(updater.UpdateError, match="no checksum"):
        updater.download(r, dest=tmp_path)


def test_download_can_be_cancelled(web, tmp_path):
    r = updater.parse_release(release_json(digest=f"sha256:{DIGEST}"))
    web[r.installer_url] = PAYLOAD
    stop = threading.Event()
    stop.set()
    with pytest.raises(Cancelled):
        updater.download(r, stop=stop, dest=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_install_command_is_silent_and_relaunches(tmp_path):
    cmd = updater.install_command(tmp_path / NAME)
    assert cmd[0].endswith(NAME)
    assert {
        "/SILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/CLOSEAPPLICATIONS",
        "/RELAUNCH=1",
    } <= set(cmd)

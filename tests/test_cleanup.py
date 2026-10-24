import os
import time

import pytest

from winsentinel import cleanup
from winsentinel.report import Cancelled, Context


def make(path, size=10, age_hours=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    if age_hours:
        old = time.time() - age_hours * 3600
        os.utime(path, (old, old))
    return path


@pytest.fixture
def temp_target(tmp_path, monkeypatch):
    root = tmp_path / "Temp"
    monkeypatch.setenv("WS_TEST_TEMP", str(root))
    return root, cleanup.Target("t", "Test temp", ("%WS_TEST_TEMP%",), aged=True)


def test_expand_env_and_globs(tmp_path, monkeypatch):
    for profile in ("Default", "Profile 1"):
        (tmp_path / "User Data" / profile / "Cache").mkdir(parents=True)
    monkeypatch.setenv("WS_TEST_BASE", str(tmp_path))
    found = cleanup.expand(r"%WS_TEST_BASE%\User Data\*\Cache")
    assert [p.parent.name for p in found] == ["Default", "Profile 1"]
    assert cleanup.expand(r"%WS_TEST_UNSET%\x") == []


def test_measure_and_clean_respect_min_age(temp_target):
    root, target = temp_target
    make(root / "old.tmp", 100, age_hours=48)
    make(root / "sub" / "old2.tmp", 50, age_hours=48)
    make(root / "new" / "fresh2.tmp", 3, age_hours=48)
    make(root / "fresh.tmp", 7)
    old = time.time() - 48 * 3600
    os.utime(root / "sub", (old, old))
    assert cleanup.measure(target, 24).bytes == 153
    assert cleanup.measure(target, 0).bytes == 160

    tally = cleanup.clean_files(target, 24, Context())
    assert (tally.files, tally.bytes) == (3, 153)
    assert (root / "fresh.tmp").exists()
    assert not (root / "sub").exists()
    assert (root / "new").exists()
    assert root.exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_never_follows_links(tmp_path, temp_target):
    root, target = temp_target
    outside = make(tmp_path / "Documents" / "precious.docx", 999, age_hours=100)
    root.mkdir(parents=True)
    try:
        (root / "link").symlink_to(outside.parent, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not allowed here")
    make(root / "junk.tmp", 5, age_hours=100)
    tally = cleanup.clean_files(target, 0, Context())
    assert tally.files == 1
    assert outside.exists()


def test_patterns_limit_what_is_deleted(tmp_path, monkeypatch):
    monkeypatch.setenv("WS_TEST_EXPLORER", str(tmp_path))
    target = cleanup.Target("x", "Thumbs", ("%WS_TEST_EXPLORER%",), patterns=("thumbcache_*.db",))
    make(tmp_path / "thumbcache_256.db")
    make(tmp_path / "ExplorerStartupLog.etl")
    cleanup.clean_files(target, 0, Context())
    assert not (tmp_path / "thumbcache_256.db").exists()
    assert (tmp_path / "ExplorerStartupLog.etl").exists()


def test_clean_reports_and_honors_stop(temp_target):
    root, target = temp_target
    make(root / "a.tmp", 10, age_hours=48)
    result = cleanup.clean([target], 24, Context())
    report = cleanup.report(result)
    assert result.total_bytes == 10
    assert "Total freed: 10 B" in report.body
    assert report.severity == "ok"

    ctx = Context()
    ctx.stop.set()
    assert cleanup.clean([target], 24, ctx).cancelled
    with pytest.raises(Cancelled):
        cleanup.analyze([target], 24, ctx)


def test_admin_targets_are_skipped_without_admin(monkeypatch, temp_target):
    root, target = temp_target
    admin_target = cleanup.Target("w", "Windows temp", target.paths, admin=True)
    make(root / "a.tmp", 10, age_hours=48)
    monkeypatch.setattr(cleanup.winapi, "is_admin", lambda: False)
    result = cleanup.clean([admin_target], 0, Context())
    assert result.results[0].error == "needs administrator"
    assert (root / "a.tmp").exists()
    assert cleanup.report(result).severity == "ok"


def test_selected_targets_default_and_saved():
    assert [t.id for t in cleanup.selected_targets(None)] == list(cleanup.DEFAULT_TARGETS)
    assert "prefetch" not in cleanup.DEFAULT_TARGETS
    assert [t.id for t in cleanup.selected_targets(["dns-cache", "user-temp"])] == [
        "user-temp",
        "dns-cache",
    ]


def test_every_target_is_well_formed():
    assert len({t.id for t in cleanup.TARGETS}) == len(cleanup.TARGETS)
    for t in cleanup.TARGETS:
        assert t.kind in ("files", "recyclebin", "dns", "dism")
        assert bool(t.paths) == (t.kind == "files")

"""GUI entry point: ``python -m winsentinel.gui`` or ``win-sentinel.exe``.

win-sentinel.exe [--minimized]   start (--minimized: straight to the tray)
win-sentinel.exe --quit          ask the running copy to exit (the installer uses it)
win-sentinel.exe --enable-startup / --disable-startup
                                 create / remove the logon task (the installer uses them)
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from types import TracebackType

logger = logging.getLogger("winsentinel")


def _log_uncaught_exceptions() -> None:
    """The installed app has no console: send crashes to the log file."""
    original = sys.excepthook

    def hook(exc_type: type[BaseException], exc: BaseException, tb: TracebackType | None) -> None:
        if not issubclass(exc_type, KeyboardInterrupt):
            logger.critical("Uncaught exception", exc_info=(exc_type, exc, tb))
        original(exc_type, exc, tb)

    sys.excepthook = hook


def _quit_on_signals(app: object) -> None:
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: QApplication.quit())
    wake = QTimer(app)  # type: ignore[arg-type]
    wake.timeout.connect(lambda: None)
    wake.start(250)


def smoke_test() -> int:
    """Build check for the packaged app: Windows APIs load and the window builds."""
    from winsentinel import __version__, paths, winapi
    from winsentinel.gui.desktop import render_icon
    from winsentinel.gui.window import MainWindow

    try:
        import keyring
        import psutil

        psutil.cpu_count()
        if winapi.WINDOWS:
            from winsentinel import authenticode, wmi

            backend = keyring.get_keyring()
            if "Windows" not in type(backend).__module__:
                raise RuntimeError(f"no usable credential store: {backend!r}")
            if not wmi.query("SELECT Caption FROM Win32_OperatingSystem"):
                raise RuntimeError("WMI returned nothing")
            status, _ = authenticode.verify(sys.executable)
            logger.info("Own signature: %s", status)
        if render_icon(64).isNull():
            raise RuntimeError("icon did not render")
        window = MainWindow()
        window.shutdown()
    except Exception:
        logger.exception("Smoke test failed")
        return 1
    logger.info("Smoke test passed (win-sentinel %s, data in %s).", __version__, paths.home())
    return 0


def _startup_task(enable: bool) -> int:
    from winsentinel import startup, wmi

    try:
        if enable:
            startup.enable()
        else:
            startup.disable()
    except wmi.WmiError as e:
        logger.error("%s", e)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        from PySide6.QtWidgets import QApplication, QSystemTrayIcon
    except ImportError:
        print("PySide6 is required for the GUI: pip install -e .", file=sys.stderr)
        return 1

    from winsentinel import APP_NAME, __version__, paths
    from winsentinel.gui.desktop import SingleInstance, SystemTrayIcon, app_icon

    parser = argparse.ArgumentParser(prog=APP_NAME, description=f"{APP_NAME} tray app")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--minimized", action="store_true", help="start in the system tray")
    parser.add_argument("--quit", action="store_true", help="ask the running copy to quit")
    parser.add_argument("--handover", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    startup_flags = parser.add_mutually_exclusive_group()
    startup_flags.add_argument("--enable-startup", action="store_true", help=argparse.SUPPRESS)
    startup_flags.add_argument("--disable-startup", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    paths.setup_logging()
    _log_uncaught_exceptions()
    if args.enable_startup or args.disable_startup:
        return _startup_task(args.enable_startup)
    app = QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("gabrielfrasantos")
    app.setWindowIcon(app_icon())
    if args.smoke_test:
        return smoke_test()

    instance = SingleInstance(parent=app)
    if args.quit:
        instance.send(b"quit")
        return 0
    if args.handover:
        instance.send(b"quit")
        deadline = time.monotonic() + 10
        while instance.is_running() and time.monotonic() < deadline:
            time.sleep(0.2)
    if instance.already_running():
        return 0

    from winsentinel.gui.update import UpdateChecker
    from winsentinel.gui.window import MainWindow

    window = MainWindow()
    tray_ok = QSystemTrayIcon.isSystemTrayAvailable()
    if tray_ok:
        tray = SystemTrayIcon(
            window,
            run_job=window.run_job,
            check_updates=window.check_for_updates,
            open_data=window.open_data_dir,
            parent=app,
        )
        tray.show()
        window.set_tray(tray)
        app.setQuitOnLastWindowClosed(False)
    instance.activated.connect(window.bring_to_front)
    instance.quit_requested.connect(app.quit)
    window.set_checker(UpdateChecker(app), automatic=paths.FROZEN)

    app.aboutToQuit.connect(window.shutdown)
    _quit_on_signals(app)
    if not (args.minimized and tray_ok):
        window.show()
    if window.tray is not None:
        window.tray.sync_menu()
    logger.info("%s %s started (data in %s).", APP_NAME, __version__, paths.home())
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

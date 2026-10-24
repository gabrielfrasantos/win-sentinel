import sys

_WINDOWS = sys.platform == "win32"

a = Analysis(
    ["winsentinel/gui/__main__.py"],
    pathex=["."],
    binaries=[],
    datas=[],
    hiddenimports=[
        "winsentinel.gui.window",
        "winsentinel.gui.update",
        "win32timezone",
        "win32com.client.dynamic",
        "pythoncom",
        "pywintypes",
        "keyring.backends.Windows",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="win-sentinel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    uac_admin=_WINDOWS,
    icon="assets/icon.ico" if _WINDOWS else "assets/icon.png",
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="win-sentinel",
)

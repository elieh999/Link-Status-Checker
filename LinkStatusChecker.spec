from __future__ import annotations

import importlib.util
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


ROOT = Path(SPECPATH)
spec = importlib.util.find_spec("mssql_python")
if spec is None or spec.origin is None:
    raise RuntimeError("mssql-python is required to build the Windows executable.")
MSSQL_ROOT = Path(spec.origin).parent

binding = next(MSSQL_ROOT.glob("ddbc_bindings*.pyd"), None)
if binding is None:
    raise RuntimeError("The mssql-python native binding was not found.")
binaries = [(str(binding), "mssql_python"), (str(MSSQL_ROOT / "msvcp140.dll"), "mssql_python")]
for path in (MSSQL_ROOT / "libs" / "windows" / "x64").rglob("*"):
    if path.is_file():
        destination = Path("mssql_python") / "libs" / "windows" / "x64" / path.relative_to(
            MSSQL_ROOT / "libs" / "windows" / "x64"
        ).parent
        binaries.append((str(path), str(destination)))

analysis = Analysis(
    ["main.py"],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=[
        (str(ROOT / "theme_light.qss"), "."),
        (str(ROOT / "assets" / "app_icon.ico"), "assets"),
    ],
    hiddenimports=collect_submodules("mssql_python"),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "PIL",
        "PySide6.QtCharts",
        "PySide6.QtDataVisualization",
        "PySide6.QtMultimedia",
        "PySide6.QtPdf",
        "PySide6.QtQml",
        "PySide6.QtQuick",
        "PySide6.QtWebEngineCore",
        "_pytest",
        "anyio",
        "attr",
        "azure",
        "bcrypt",
        "certifi",
        "cffi",
        "charset_normalizer",
        "cryptography",
        "idna",
        "matplotlib",
        "msal",
        "numpy",
        "pandas",
        "pygments",
        "pytest",
        "requests",
        "setuptools",
        "sniffio",
        "tkinter",
        "trio",
        "urllib3",
    ],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(analysis.pure)
exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="LinkStatusChecker",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[str(ROOT / "assets" / "app_icon.ico")],
    version=str(ROOT / "version_info.txt"),
)

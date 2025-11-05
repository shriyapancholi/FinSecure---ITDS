# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['desktop_boot.py'],                 # ✅ start the desktop wrapper
    pathex=[],
    binaries=[],
    datas=[
        ('app.py', '.'),                 # ✅ your Flask backend
        ('templates', 'templates'),      # ✅ Jinja templates
        ('static', 'static'),            # ✅ CSS/JS/assets
        ('finsecure.db', '.'),           # (optional) seed DB
        ('.env', '.'),                   # (optional) dotenv for local runs
    ],
    hiddenimports=[
        'flask_limiter',
        'flask_limiter.util',
        'werkzeug.middleware.proxy_fix',
        'dotenv',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='FinSecure',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,            # windowed app
    disable_windowed_traceback=False,
    argv_emulation=True,      # good on macOS for drag/drop/open handling
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# macOS .app bundle (safe to keep for Windows/Linux; PyInstaller ignores it)
app = BUNDLE(
    exe,
    name='FinSecure.app',
    icon=None,                # add your .icns if you have one
    bundle_identifier='com.finsecure.itds',
)
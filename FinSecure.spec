# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['desktop_boot.py'],          # ✅ entry = desktop wrapper
    pathex=[],
    binaries=[],
    datas=[
        ('app.py', '.'),          # ✅ Flask backend file
        ('templates', 'templates'),
        ('static', 'static'),
        ('finsecure.db', '.'),    # optional seed DB
        ('.env', '.'),            # optional env file
    ],
    hiddenimports=[
        # Flask / middleware / limiter
        'werkzeug.middleware.proxy_fix',
        'flask_limiter',
        'flask_limiter.util',
        'dotenv',
        'requests',
        # ✅ critical for mac build where sqlite sometimes fails to hook
        'sqlite3',
        '_sqlite3',
        # Desktop WebView (usually auto-detected, keep as safety)
        'webview',
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
    console=False,            # ✅ windowed app
    disable_windowed_traceback=False,
    argv_emulation=True,      # ✅ macOS drag/drop/open handling
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# ✅ App bundle with your icon (place FinSecure.icns in project root)
app = BUNDLE(
    exe,
    name='FinSecure.app',
    icon='FinSecure.icns',
    bundle_identifier='com.finsecure.itds',
)
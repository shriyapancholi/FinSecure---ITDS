# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['desktop_boot.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('app.py', '.'),            # Flask backend
        ('templates', 'templates'),
        ('static', 'static'),
        ('finsecure.db', '.'),      # seed DB (optional)
        ('.env', '.'),              # optional
    ],
    hiddenimports=[
        'werkzeug.middleware.proxy_fix',
        'flask_limiter',
        'flask_limiter.util',
        'dotenv',
        # >>> critical for your crash:
        'sqlite3',
        '_sqlite3',
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
    console=False,           # windowed
    disable_windowed_traceback=False,
    argv_emulation=True,     # macOS friendly
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

app = BUNDLE(
    exe,
    name='FinSecure.app',
    icon=None,
    bundle_identifier='com.finsecure.itds',
)
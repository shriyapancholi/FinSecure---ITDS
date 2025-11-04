# wsgi.py
"""
Robust WSGI loader for Gunicorn.
It tries a few likely module locations to find a Flask 'app' object
and exposes it as `app` and `application` for compatibility.
"""

import importlib
import sys
from types import ModuleType

CANDIDATES = [
    # common places your app might live
    "app.app",     # e.g. app/app.py -> contains `app = Flask(...)`
    "app.main",    # e.g. app/main.py
    "main",        # top-level main.py or app.py renamed to main.py
    "app",         # package - will import package __init__ (less preferred)
    "run",         # run.py
    "wsgi_module", # any other
]

found = None
errors = []

for modname in CANDIDATES:
    try:
        mod = importlib.import_module(modname)
        # look for 'app' object (Flask)
        if hasattr(mod, "app"):
            found = getattr(mod, "app")
            break
        # alternative names
        if hasattr(mod, "application"):
            found = getattr(mod, "application")
            break
    except Exception as e:
        errors.append((modname, str(e)))
        continue

if found is None:
    # as a last attempt, try top-level "app.py" module by filename
    try:
        mod = importlib.import_module("app")  # this may import package; ignore errors
        if hasattr(mod, "app"):
            found = getattr(mod, "app")
    except Exception:
        pass

if found is None:
    msg = (
        "Could not locate Flask 'app' object in known locations. "
        "Checked: {}\nErrors: {}\n".format(", ".join(CANDIDATES), errors)
    )
    raise ImportError(msg)

# Expose both names (some servers expect 'application', some expect 'app')
app = found
application = found
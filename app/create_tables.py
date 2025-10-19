# app/create_tables.py
"""
Create DB tables for the app.

Recommended invocation:
    python -m app.create_tables
or from a Python REPL:
    import app.create_tables
    app.create_tables.init_db()
"""

from app.database import Base, engine
# import models module so all models register with Base.metadata
from app import models
import sys
import traceback

def init_db():
    print("Creating tables if they do not exist...")
    try:
        Base.metadata.create_all(bind=engine)
        print("Done.")
    except Exception as e:
        print("Failed to create tables:")
        traceback.print_exc(file=sys.stdout)
        raise

if __name__ == "__main__":
    # Prefer running as a module to ensure package imports work:
    # python -m app.create_tables
    init_db()
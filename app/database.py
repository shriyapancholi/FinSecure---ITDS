# database.py — dual-mode (SQLite for dev, MySQL for prod) + SQLAlchemy setup
import os
from dotenv import load_dotenv
from urllib.parse import quote_plus
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

load_dotenv()

# -------------------------
# Configuration (env-driven)
# -------------------------
DB_DRIVER = os.getenv("DB_DRIVER", "sqlite").lower()  # "sqlite" or "mysql"
FINSEC_SQLITE_PATH = os.getenv("FINSEC_DB", os.path.join(os.path.dirname(__file__), "finsecure.db"))

# MySQL settings (only used if DB_DRIVER=mysql)
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "change_me_in_env")
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "finsecure")

# -------------------------
# Build SQLAlchemy DATABASE_URL
# -------------------------
if DB_DRIVER == "mysql":
    password_quoted = quote_plus(DB_PASSWORD)
    DATABASE_URL = f"mysql+pymysql://{DB_USER}:{password_quoted}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
else:
    # default SQLite for local dev
    DATABASE_URL = f"sqlite:///{FINSEC_SQLITE_PATH}"

# -------------------------
# Create engine & session
# -------------------------
# echo=True can be useful for debugging; set via env if needed
ECHO = os.getenv("SQLALCHEMY_ECHO", "False").lower() in ("1", "true", "yes")
try:
    engine = create_engine(DATABASE_URL, echo=ECHO, future=True)
except ModuleNotFoundError as e:
    raise ModuleNotFoundError(
        "Database driver not found. If you intended to use MySQL, install pymysql:\n"
        "    pip install pymysql\n"
        f"Original error: {e}"
    ) from e

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,
    future=True,
)

Base = declarative_base()

# -------------------------
# FastAPI dependency
# -------------------------
def get_db():
    """Yield a database session for FastAPI dependency injection."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -------------------------
# Helpers: init & test
# -------------------------
def init_db(import_models_callable=None):
    """
    Create all tables if they don't exist.
    Optionally accept a callable that will import/register models before create_all.
    Example usage:
      from app import models
      init_db()
    """
    # If caller provided a callable to import models, run it.
    if import_models_callable:
        import_models_callable()

    # Otherwise it's expected that app modules import models before calling init_db.
    Base.metadata.create_all(bind=engine)

def test_connection():
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            print("✅ Database connection OK:", DATABASE_URL)
    except Exception as e:
        print("❌ Database connection failed:", e)

# -------------------------
# Run manual test / init
# -------------------------
if __name__ == "__main__":
    test_connection()
    # For convenience: import app models here if you want init_db to create tables automatically.
    # Example (uncomment and adapt): 
    # import app.models  # ensures models are registered with Base
    # init_db()
    print("✅ database.py loaded (no tables created automatically).")
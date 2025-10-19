import os
from dotenv import load_dotenv
from urllib.parse import quote_plus
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

load_dotenv()  # Load .env into environment

# --- DB Config ---
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "change_me_in_env")  # set via .env or export
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "finsecure")

# URL encode password (handles special chars like @, #, etc.)
password_quoted = quote_plus(DB_PASSWORD)
DATABASE_URL = f"mysql+pymysql://{DB_USER}:{password_quoted}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# --- Engine ---
try:
    engine = create_engine(DATABASE_URL, echo=True, pool_pre_ping=True)
except ModuleNotFoundError as e:
    raise ModuleNotFoundError(
        "Database driver not found. If you are using MySQL, install pymysql:\n"
        "    pip install pymysql\n"
        f"Original error: {e}"
    ) from e

# --- Session & Base ---
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,  # keeps data accessible after commit
    future=True,
)
Base = declarative_base()


# ✅ Add this: FastAPI dependency for DB sessions
def get_db():
    """Yield a database session for FastAPI dependency injection."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ✅ Optional: auto-create tables if not existing (safe for dev/demo)
def init_db():
    """Create all tables if they don't exist (safe to call on startup)."""
    from threat_detection.responses_model import Response  # import your models here
    # You can import more models as needed
    Base.metadata.create_all(bind=engine)


# ✅ Connection test utility
def test_connection():
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            print("✅ Database connection OK")
    except Exception as e:
        print("❌ Database connection failed:")
        print(e)


# --- Run manually to test connection ---
if __name__ == "__main__":
    test_connection()
    init_db()
    print("✅ Tables verified or created successfully.")
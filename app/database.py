# app/database.py
import os
from dotenv import load_dotenv
from urllib.parse import quote_plus

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

load_dotenv()  # load .env into environment

# Read values from environment (or use safe defaults for dev)
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "change_me_in_env")  # set via .env or export
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "finsecure")

# URL encode password (handles special chars like @, #, etc.)
password_quoted = quote_plus(DB_PASSWORD)
DATABASE_URL = f"mysql+pymysql://{DB_USER}:{password_quoted}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Create the SQLAlchemy engine (give helpful feedback if driver missing)
try:
    engine = create_engine(DATABASE_URL, echo=True, pool_pre_ping=True)
except ModuleNotFoundError as e:
    # Most likely missing the DB driver (pymysql) — give actionable message
    raise ModuleNotFoundError(
        "Database driver not found. If you are using MySQL, install pymysql:\n"
        "    pip install pymysql\n"
        f"Original error: {e}"
    ) from e

# Session factory (SQLAlchemy 2.x compatible)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,  # keeps data accessible after commit
    future=True,
)

Base = declarative_base()


def test_connection():
    """Quick connection test"""
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            print("✅ Database connection OK")
    except Exception as e:
        print("❌ Database connection failed:")
        print(e)


if __name__ == "__main__":
    test_connection()
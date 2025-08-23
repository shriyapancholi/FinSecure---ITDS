# create_tables.py
from app.database import Base, engine
import app.models  # ensure models are imported so they're registered with Base

def init_db():
    print("Creating tables if they do not exist...")
    Base.metadata.create_all(bind=engine)
    print("Done.")

if __name__ == "__main__":
    init_db()

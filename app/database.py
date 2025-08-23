# app/database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# For dev: using root. In prod, create a dedicated MySQL user with limited privileges.
DATABASE_URL = "mysql+pymysql://root:Shriya%4045@localhost:3306/finsecure"

engine = create_engine(DATABASE_URL, echo=True)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False  # keep attributes loaded after commit
)

Base = declarative_base()
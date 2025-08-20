from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# IMPORTANT: use insiderthreat, not root
DATABASE_URL = "mysql+pymysql://root:Shriya%4045@localhost:3306/finsecure"

engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
from app.database import Base, engine
import app.models

print("Creating tables...")
Base.metadata.create_all(bind=engine)
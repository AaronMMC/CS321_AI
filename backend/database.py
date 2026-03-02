from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from backend.config import settings

# Connect to the SQLite file defined in config
# check_same_thread=False is required for SQLite with FastAPI
SQLALCHEMY_DATABASE_URL = f"sqlite:///{settings.DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency to get a database session in your routers
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
"""
Database session management
"""
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

# Convert PostgresDsn to string for SQLAlchemy
database_url = str(settings.DATABASE_URL)

# Create SQLAlchemy engine
engine = create_engine(database_url)

# Create sessionmaker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create Base class for models
Base = declarative_base()

def get_db() -> Generator:
    """
    Get a database session
    
    Yields:
        A database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

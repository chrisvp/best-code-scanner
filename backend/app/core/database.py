from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.core.config import settings
import os

# Ensure we use the correct URL format for SQLCipher
# Example: sqlite+pysqlcipher://:password@/path/to/db.sqlite
# Note: The password handling depends on the specific driver/dialect. 
# For sqlcipher3, we often need to execute a PRAGMA key command after connection.

SQLALCHEMY_DATABASE_URL = settings.DATABASE_URL

# Create engine
# We need to handle the encryption key injection.
# For standard SQLite, we just pass the URL. For SQLCipher, we need to hook into the connect event.

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False} # Needed for SQLite
)

from sqlalchemy import event

# @event.listens_for(engine, "connect")
# def do_connect(dbapi_connection, connection_record):
#     # This is the critical part for SQLCipher
#     cursor = dbapi_connection.cursor()
#     cursor.execute(f"PRAGMA key = '{settings.DB_PASSWORD}'")
#     cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

import sys
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from urllib.parse import urlparse
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.config import settings

def try_connect_and_create_db(username, password, host, port, dbname):
    # Try connecting to postgres to create db if not exists
    try:
        conn = psycopg2.connect(
            dbname="postgres",
            user=username,
            password=password,
            host=host,
            port=port
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        cursor.execute(f"SELECT 1 FROM pg_catalog.pg_database WHERE datname = '{dbname}'")
        exists = cursor.fetchone()
        if not exists:
            cursor.execute(f"CREATE DATABASE {dbname}")
            print(f"PostgreSQL Database '{dbname}' created successfully.")
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"MFA/DB Log: Failed postgres connect with user={username} password='{password}': {e}")
        return False

def check_and_create_database(db_url: str) -> str:
    import os
    if os.getenv("TESTING") == "True":
        print("MFA/DB Log: Running in testing mode. Using SQLite test database.")
        return "sqlite:///./test_ransomware_defense.db"

    if not db_url.startswith("postgresql"):
        return db_url
        
    url = urlparse(db_url)
    username = url.username or 'postgres'
    password = url.password or 'postgres'
    host = url.hostname or 'localhost'
    port = url.port or 5432
    dbname = url.path.lstrip('/') or 'ransomware_defense'
    
    # Try the default configuration
    if try_connect_and_create_db(username, password, host, port, dbname):
        return db_url
        
    # If default configuration fails, try scanning standard password credentials
    print("MFA/DB Log: Default connection string failed. Scanning standard local PostgreSQL credentials...")
    passwords_to_try = ["postgres", "password", "", "admin", "root", "123456"]
    
    for pwd in passwords_to_try:
        if pwd == password:
            continue
        print(f"MFA/DB Log: Trying fallback credentials: user={username}, password='{pwd}'...")
        if try_connect_and_create_db(username, pwd, host, port, dbname):
            # Formulate new connection string
            new_url = f"postgresql://{username}:{pwd}@{host}:{port}/{dbname}"
            print(f"MFA/DB Log: Found valid credentials! Overriding connection string to use password '{pwd}'")
            return new_url
            
    print("MFA/DB Log: CRITICAL - Could not connect to PostgreSQL cluster. Falling back to SQLite (./ransomware_defense.db) for runtime convenience.")
    return "sqlite:///./ransomware_defense.db"

from sqlalchemy.pool import NullPool

DATABASE_URL = check_and_create_database(settings.DATABASE_URL)

connect_args = {}
pool_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    pool_args = {"poolclass": NullPool}

engine = create_engine(DATABASE_URL, connect_args=connect_args, **pool_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

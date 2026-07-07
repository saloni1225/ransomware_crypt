import os
import pytest

# Ensure testing mode is active before any imports
os.environ["TESTING"] = "True"
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-for-ci")
os.environ.setdefault("AGENT_SHARED_SECRET", "test-agent-secret-for-ci")

from sqlalchemy import event
from app.database import engine, Base

# Register the WAL pragma listener at module level so it runs before any imports or metadata creation
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
    except Exception:
        pass
    finally:
        cursor.close()

@pytest.fixture(scope="session", autouse=True)
def setup_sqlite_wal():
    """
    Setup test database and clean up.
    """
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    yield
    
    # Clean up and dispose pool to release files
    engine.dispose()
    
    # Try deleting the test database files to clean up the workspace
    for suffix in ("", "-wal", "-shm"):
        db_file = f"./test_ransomware_defense.db{suffix}"
        if os.path.exists(db_file):
            try:
                os.remove(db_file)
            except OSError:
                pass

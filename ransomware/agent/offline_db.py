import sqlite3
import os
import json
import logging
import time

logger = logging.getLogger("agent.offline_db")

class OfflineDB:
    def __init__(self, db_path: str, max_size: int = 5000):
        self.db_path = db_path
        self.max_size = max_size
        self._init_db()

    def _init_db(self):
        # Create database file and connection
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload TEXT,
                    created_at REAL
                )
            """)
            conn.commit()
        finally:
            conn.close()
            
        # Restrict permissions to owner (read/write only)
        try:
            os.chmod(self.db_path, 0o600)
        except Exception as e:
            logger.debug("Failed to set file permissions 0o600: %s", e)

    def enqueue(self, event: dict):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Count to enforce FIFO pruning
            cursor.execute("SELECT COUNT(*) FROM events")
            count = cursor.fetchone()[0]
            if count >= self.max_size:
                to_delete = count - self.max_size + 1
                cursor.execute(
                    "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT ?)",
                    (to_delete,)
                )
                logger.warning("Offline buffer capacity reached. Pruned %d oldest events.", to_delete)
                
            cursor.execute(
                "INSERT INTO events (payload, created_at) VALUES (?, ?)",
                (json.dumps(event), time.time())
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error("Failed to enqueue event to offline DB: %s", e)

    def get_batch(self, batch_size: int) -> list:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, payload FROM events ORDER BY id ASC LIMIT ?",
                (batch_size,)
            )
            rows = cursor.fetchall()
            conn.close()
            return [{"id": r[0], "event": json.loads(r[1])} for r in rows]
        except Exception as e:
            logger.error("Failed to fetch batch from offline DB: %s", e)
            return []

    def delete_batch(self, ids: list):
        if not ids:
            return
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            placeholders = ",".join("?" for _ in ids)
            cursor.execute(
                f"DELETE FROM events WHERE id IN ({placeholders})",
                tuple(ids)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error("Failed to delete batch from offline DB: %s", e)
            
    def get_count(self) -> int:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM events")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception:
            return 0

"""
Unit tests for Database class.
"""

import pytest
import sqlite3
import os
import tempfile
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app import Database, Metadata


class TestDatabase:
    """Tests for Database operations."""

    @pytest.fixture
    def db(self):
        """Create a temporary database for each test."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        
        database = Database(db_path)
        yield database
        
        try:
            os.unlink(db_path)
        except:
            pass

    def test_init_creates_tables(self, db):
        """Database initialization should create required tables."""
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        
        # Check sessions table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'")
        assert cursor.fetchone() is not None
        
        # Check messages table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'")
        assert cursor.fetchone() is not None
        
        conn.close()

    def test_save_session_without_metadata(self, db):
        """Should save session with default metadata."""
        db.save_session("session-001")
        
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sessions WHERE session_id = ?", ("session-001",))
        row = cursor.fetchone()
        conn.close()
        
        assert row is not None
        assert row[0] == "session-001"  # session_id
        assert row[1] == "SMS"           # default channel
        assert row[2] == "English"       # default language
        assert row[3] == "IN"            # default locale

    def test_save_session_with_metadata(self, db):
        """Should save session with provided metadata."""
        metadata = Metadata(channel="WhatsApp", language="Hindi", locale="IN")
        db.save_session("session-002", metadata)
        
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sessions WHERE session_id = ?", ("session-002",))
        row = cursor.fetchone()
        conn.close()
        
        assert row[1] == "WhatsApp"
        assert row[2] == "Hindi"

    def test_save_session_updates_existing(self, db):
        """Should update existing session on duplicate save."""
        db.save_session("session-003")
        db.save_session("session-003", Metadata(channel="Email"))
        
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM sessions WHERE session_id = ?", ("session-003",))
        count = cursor.fetchone()[0]
        conn.close()
        
        assert count == 1  # Only one record

    def test_save_message(self, db):
        """Should save message to database."""
        db.save_message("session-001", "scammer", "Hello, verify your account!")
        
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM messages WHERE session_id = ?", ("session-001",))
        row = cursor.fetchone()
        conn.close()
        
        assert row is not None
        assert row[1] == "session-001"    # session_id
        assert row[2] == "scammer"        # sender
        assert row[3] == "Hello, verify your account!"  # text

    def test_save_response_message(self, db):
        """Should save response message with is_response flag."""
        db.save_message("session-001", "user", "What do you mean?", is_response=True)
        
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT is_response FROM messages WHERE session_id = ?", ("session-001",))
        row = cursor.fetchone()
        conn.close()
        
        assert row[0] == 1  # is_response = True

    def test_multiple_messages_same_session(self, db):
        """Should save multiple messages for same session."""
        db.save_message("session-001", "scammer", "Message 1")
        db.save_message("session-001", "user", "Response 1", is_response=True)
        db.save_message("session-001", "scammer", "Message 2")
        
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM messages WHERE session_id = ?", ("session-001",))
        count = cursor.fetchone()[0]
        conn.close()
        
        assert count == 3

    def test_message_has_timestamp(self, db):
        """Saved message should have timestamp."""
        db.save_message("session-001", "scammer", "Test message")
        
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp FROM messages WHERE session_id = ?", ("session-001",))
        row = cursor.fetchone()
        conn.close()
        
        assert row[0] is not None

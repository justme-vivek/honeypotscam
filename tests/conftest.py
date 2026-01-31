"""
Pytest configuration and shared fixtures for all tests.
"""

import pytest
import os
import sys
import tempfile

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from app import app, Database, API_KEY


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


@pytest.fixture
def auth_headers():
    """Return headers with valid API key."""
    return {"x-api-key": API_KEY}


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    
    db = Database(db_path)
    yield db
    
    # Cleanup
    try:
        os.unlink(db_path)
    except:
        pass


@pytest.fixture
def sample_scam_message():
    """Sample scam message request body."""
    return {
        "sessionId": "test-session-001",
        "message": {
            "sender": "scammer",
            "text": "URGENT! Your bank account has been blocked. Share OTP immediately to verify."
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }


@pytest.fixture
def sample_lottery_scam():
    """Sample lottery scam message."""
    return {
        "sessionId": "test-session-002",
        "message": {
            "sender": "scammer",
            "text": "Congratulations! You have won $1,000,000 in the lottery! Click here to claim your prize now!"
        }
    }


@pytest.fixture
def sample_benign_message():
    """Sample non-scam message."""
    return {
        "sessionId": "test-session-003",
        "message": {
            "sender": "user",
            "text": "Hello, how are you doing today?"
        }
    }

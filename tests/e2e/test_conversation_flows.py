"""
End-to-end tests for complete scam conversation flows.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fastapi.testclient import TestClient
from app import app, API_KEY


class TestBankingScamFlow:
    """E2E tests for banking scam conversation."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    @pytest.fixture
    def auth_headers(self):
        return {"x-api-key": API_KEY}

    def test_banking_scam_multi_turn_conversation(self, client, auth_headers):
        """Simulate a multi-turn banking scam conversation."""
        session_id = "e2e-banking-001"
        history = []
        
        # Turn 1: Initial scam message
        response = client.post("/api/chat", headers=auth_headers, json={
            "sessionId": session_id,
            "message": {"sender": "scammer", "text": "Dear customer, your SBI account has been blocked due to suspicious activity."},
            "conversationHistory": history
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["analysis"]["scam_type"] == "banking_fraud"
        
        history.append({"sender": "scammer", "text": "Dear customer, your SBI account has been blocked."})
        history.append({"sender": "user", "text": data["response"]["text"]})
        
        # Turn 2: Scammer escalates
        response = client.post("/api/chat", headers=auth_headers, json={
            "sessionId": session_id,
            "message": {"sender": "scammer", "text": "Please share your OTP immediately to unblock your account!"},
            "conversationHistory": history
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["analysis"]["confidence"] > 0
        
        # Turn 3: Continued engagement
        history.append({"sender": "scammer", "text": "Please share your OTP!"})
        history.append({"sender": "user", "text": data["response"]["text"]})
        
        response = client.post("/api/chat", headers=auth_headers, json={
            "sessionId": session_id,
            "message": {"sender": "scammer", "text": "This is urgent! Your money will be lost!"},
            "conversationHistory": history
        })
        
        assert response.status_code == 200
        assert response.json()["status"] == "success"


class TestLotteryScamFlow:
    """E2E tests for lottery scam conversation."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    @pytest.fixture
    def auth_headers(self):
        return {"x-api-key": API_KEY}

    def test_lottery_scam_detection_and_response(self, client, auth_headers):
        """Test lottery scam detection across multiple messages."""
        session_id = "e2e-lottery-001"
        
        # First message
        response = client.post("/api/chat", headers=auth_headers, json={
            "sessionId": session_id,
            "message": {"text": "Congratulations! You have WON $5,000,000 in the International Lottery!"}
        })
        
        data = response.json()
        assert data["analysis"]["scam_type"] == "lottery_scam"
        
        # Follow-up
        response = client.post("/api/chat", headers=auth_headers, json={
            "sessionId": session_id,
            "message": {"text": "To claim your prize, send $500 processing fee immediately!"},
            "conversationHistory": [
                {"sender": "scammer", "text": "You have WON $5,000,000!"},
                {"sender": "user", "text": data["response"]["text"]}
            ]
        })
        
        assert response.status_code == 200
        # Should still engage the scammer
        assert len(response.json()["response"]["text"]) > 0


class TestSessionPersistence:
    """E2E tests for session management."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    @pytest.fixture
    def auth_headers(self):
        return {"x-api-key": API_KEY}

    def test_session_id_consistency(self, client, auth_headers):
        """Same session ID should be maintained across requests."""
        session_id = "persistent-session-001"
        
        for i in range(3):
            response = client.post("/api/chat", headers=auth_headers, json={
                "sessionId": session_id,
                "message": {"text": f"Message number {i+1}"}
            })
            
            assert response.json()["sessionId"] == session_id

    def test_multiple_independent_sessions(self, client, auth_headers):
        """Multiple sessions should work independently."""
        sessions = ["session-a", "session-b", "session-c"]
        
        for session_id in sessions:
            response = client.post("/api/chat", headers=auth_headers, json={
                "sessionId": session_id,
                "message": {"text": "Test message for " + session_id}
            })
            
            assert response.status_code == 200
            assert response.json()["sessionId"] == session_id


class TestEdgeCases:
    """E2E tests for edge cases and error handling."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    @pytest.fixture
    def auth_headers(self):
        return {"x-api-key": API_KEY}

    def test_empty_message(self, client, auth_headers):
        """Empty message should still get a response."""
        response = client.post("/api/chat", headers=auth_headers, json={
            "sessionId": "empty-test",
            "message": {"text": ""}
        })
        
        assert response.status_code == 200
        assert response.json()["analysis"]["scam_type"] == "unknown"

    def test_very_long_message(self, client, auth_headers):
        """Very long message should be handled."""
        long_text = "Urgent! " * 500 + "Bank blocked! " * 500
        
        response = client.post("/api/chat", headers=auth_headers, json={
            "sessionId": "long-message-test",
            "message": {"text": long_text}
        })
        
        assert response.status_code == 200

    def test_special_characters_in_message(self, client, auth_headers):
        """Special characters should be handled."""
        response = client.post("/api/chat", headers=auth_headers, json={
            "sessionId": "special-chars",
            "message": {"text": "Hello! @#$%^&*() 你好 🎉 <script>alert('xss')</script>"}
        })
        
        assert response.status_code == 200

    def test_minimal_request_body(self, client, auth_headers):
        """Minimal request should work."""
        response = client.post("/api/chat", headers=auth_headers, json={})
        
        assert response.status_code == 200

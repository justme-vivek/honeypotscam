"""
Integration tests for FastAPI endpoints.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fastapi.testclient import TestClient
from app import app, API_KEY


class TestHealthEndpoint:
    """Tests for /health endpoint."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_health_returns_200(self, client):
        """Health check should return 200 OK."""
        response = client.get("/health")
        
        assert response.status_code == 200

    def test_health_returns_healthy_status(self, client):
        """Health check should return healthy status."""
        response = client.get("/health")
        data = response.json()
        
        assert data["status"] == "healthy"
        assert data["service"] == "honeypot-scam-api"
        assert data["version"] == "1.0.0"

    def test_health_no_auth_required(self, client):
        """Health endpoint should work without API key."""
        response = client.get("/health")
        
        assert response.status_code == 200


class TestMetricsEndpoint:
    """Tests for /metrics endpoint."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    @pytest.fixture
    def auth_headers(self):
        return {"x-api-key": API_KEY}

    def test_metrics_requires_auth(self, client):
        """Metrics endpoint should require API key."""
        response = client.get("/metrics")
        
        assert response.status_code == 401

    def test_metrics_returns_stats(self, client, auth_headers):
        """Metrics should return service statistics."""
        response = client.get("/metrics", headers=auth_headers)
        data = response.json()
        
        assert response.status_code == 200
        assert "requests_received" in data
        assert "scams_detected" in data
        assert "active_sessions" in data
        assert "uptime_seconds" in data

    def test_metrics_with_invalid_key(self, client):
        """Invalid API key should be rejected."""
        response = client.get("/metrics", headers={"x-api-key": "invalid"})
        
        assert response.status_code == 401


class TestChatEndpoint:
    """Tests for /api/chat endpoint."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    @pytest.fixture
    def auth_headers(self):
        return {"x-api-key": API_KEY}

    def test_chat_requires_auth(self, client):
        """Chat endpoint should require API key."""
        response = client.post("/api/chat", json={"message": {"text": "test"}})
        
        assert response.status_code == 401

    def test_chat_with_valid_scam_message(self, client, auth_headers):
        """Should process scam message and return response."""
        payload = {
            "sessionId": "test-session",
            "message": {
                "sender": "scammer",
                "text": "Your bank account is blocked! Share OTP now!"
            }
        }
        
        response = client.post("/api/chat", json=payload, headers=auth_headers)
        data = response.json()
        
        assert response.status_code == 200
        assert data["status"] == "success"
        assert "response" in data
        assert data["response"]["sender"] == "user"
        assert len(data["response"]["text"]) > 0

    def test_chat_returns_analysis(self, client, auth_headers):
        """Should include scam analysis in response."""
        payload = {
            "message": {
                "text": "URGENT! Bank blocked! Share OTP immediately!"
            }
        }
        
        response = client.post("/api/chat", json=payload, headers=auth_headers)
        data = response.json()
        
        assert "analysis" in data
        assert "scam_type" in data["analysis"]
        assert "confidence" in data["analysis"]
        assert "risk_level" in data["analysis"]

    def test_chat_generates_session_id(self, client, auth_headers):
        """Should generate session ID if not provided."""
        payload = {"message": {"text": "Hello"}}
        
        response = client.post("/api/chat", json=payload, headers=auth_headers)
        data = response.json()
        
        assert "sessionId" in data
        assert data["sessionId"].startswith("session_")

    def test_chat_preserves_session_id(self, client, auth_headers):
        """Should preserve provided session ID."""
        payload = {
            "sessionId": "my-custom-session-123",
            "message": {"text": "Test message"}
        }
        
        response = client.post("/api/chat", json=payload, headers=auth_headers)
        data = response.json()
        
        assert data["sessionId"] == "my-custom-session-123"

    def test_chat_accepts_simple_text_format(self, client, auth_headers):
        """Should accept message as simple text."""
        payload = {
            "message": "Simple text message"
        }
        
        response = client.post("/api/chat", json=payload, headers=auth_headers)
        
        assert response.status_code == 200

    def test_chat_accepts_text_at_root(self, client, auth_headers):
        """Should accept text at root level."""
        payload = {
            "text": "Root level text"
        }
        
        response = client.post("/api/chat", json=payload, headers=auth_headers)
        
        assert response.status_code == 200

    def test_chat_with_conversation_history(self, client, auth_headers):
        """Should accept conversation history."""
        payload = {
            "sessionId": "history-test",
            "message": {"text": "New message"},
            "conversationHistory": [
                {"sender": "scammer", "text": "First message"},
                {"sender": "user", "text": "First response"}
            ]
        }
        
        response = client.post("/api/chat", json=payload, headers=auth_headers)
        
        assert response.status_code == 200

    def test_chat_includes_timestamp(self, client, auth_headers):
        """Response should include timestamp."""
        payload = {"message": {"text": "Test"}}
        
        response = client.post("/api/chat", json=payload, headers=auth_headers)
        data = response.json()
        
        assert "timestamp" in data["response"]

    def test_chat_rejects_invalid_json(self, client, auth_headers):
        """Invalid JSON should return 400 error."""
        response = client.post(
            "/api/chat",
            content="not valid json",
            headers={**auth_headers, "content-type": "application/json"}
        )
        
        assert response.status_code == 400

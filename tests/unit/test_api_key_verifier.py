"""
Unit tests for APIKeyVerifier class.
"""

import pytest
from unittest.mock import MagicMock
from fastapi import HTTPException
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app import APIKeyVerifier, API_KEY


class TestAPIKeyVerifier:
    """Tests for API key verification."""

    def test_valid_api_key(self):
        """Valid API key should pass verification."""
        mock_request = MagicMock()
        mock_request.headers.get.return_value = API_KEY
        
        result = APIKeyVerifier.verify(mock_request)
        
        assert result is True

    def test_missing_api_key(self):
        """Missing API key should raise 401 error."""
        mock_request = MagicMock()
        mock_request.headers.get.return_value = None
        
        with pytest.raises(HTTPException) as exc_info:
            APIKeyVerifier.verify(mock_request)
        
        assert exc_info.value.status_code == 401
        assert "Missing x-api-key" in exc_info.value.detail

    def test_invalid_api_key(self):
        """Invalid API key should raise 401 error."""
        mock_request = MagicMock()
        mock_request.headers.get.return_value = "wrong-api-key"
        
        with pytest.raises(HTTPException) as exc_info:
            APIKeyVerifier.verify(mock_request)
        
        assert exc_info.value.status_code == 401
        assert "Invalid API key" in exc_info.value.detail

    def test_empty_api_key(self):
        """Empty string API key should raise 401 error."""
        mock_request = MagicMock()
        mock_request.headers.get.return_value = ""
        
        with pytest.raises(HTTPException) as exc_info:
            APIKeyVerifier.verify(mock_request)
        
        assert exc_info.value.status_code == 401

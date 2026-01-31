"""
Unit tests for HoneypotResponder class.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app import HoneypotResponder


class TestHoneypotResponder:
    """Tests for HoneypotResponder response generation."""

    def test_generate_response_returns_string(self):
        """Response should be a non-empty string."""
        response = HoneypotResponder.generate_response()
        
        assert isinstance(response, str)
        assert len(response) > 0

    def test_response_from_predefined_list(self):
        """Response should be from the predefined RESPONSES list."""
        response = HoneypotResponder.generate_response()
        
        assert response in HoneypotResponder.RESPONSES

    def test_response_randomness(self):
        """Multiple calls should produce varied responses (probabilistic)."""
        responses = set()
        for _ in range(50):
            responses.add(HoneypotResponder.generate_response())
        
        # With 17 possible responses, 50 calls should hit at least 3 different ones
        assert len(responses) >= 3

    def test_response_with_history_length(self):
        """Response generation should accept history_length parameter."""
        response = HoneypotResponder.generate_response(history_length=5)
        
        assert isinstance(response, str)
        assert response in HoneypotResponder.RESPONSES

    def test_response_with_zero_history(self):
        """Zero history length should work."""
        response = HoneypotResponder.generate_response(history_length=0)
        
        assert isinstance(response, str)

    def test_responses_list_not_empty(self):
        """RESPONSES list should have multiple options."""
        assert len(HoneypotResponder.RESPONSES) > 10

    def test_responses_are_engaging(self):
        """Responses should contain engaging phrases."""
        engaging_patterns = ["?", "!", "wait", "hold", "help", "please"]
        
        has_engaging = False
        for response in HoneypotResponder.RESPONSES:
            if any(pattern in response.lower() for pattern in engaging_patterns):
                has_engaging = True
                break
        
        assert has_engaging

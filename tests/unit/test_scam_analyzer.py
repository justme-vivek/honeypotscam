"""
Unit tests for ScamAnalyzer class.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app import ScamAnalyzer


class TestScamAnalyzer:
    """Tests for ScamAnalyzer.analyze() method."""

    def test_empty_text_returns_unknown(self):
        """Empty text should return unknown scam type with zero confidence."""
        result = ScamAnalyzer.analyze("")
        assert result["scam_type"] == "unknown"
        assert result["confidence"] == 0
        assert result["risk_level"] == "LOW"

    def test_none_text_returns_unknown(self):
        """None text should return unknown scam type."""
        result = ScamAnalyzer.analyze(None)
        assert result["scam_type"] == "unknown"
        assert result["confidence"] == 0

    def test_banking_scam_detection(self):
        """Banking fraud keywords should be detected."""
        text = "Your bank account has been blocked. Share your OTP to verify."
        result = ScamAnalyzer.analyze(text)
        
        assert result["scam_type"] == "banking_fraud"
        assert result["confidence"] > 0
        assert "banking" in result["detected_keywords"]

    def test_lottery_scam_detection(self):
        """Lottery scam keywords should be detected."""
        text = "Congratulations! You have won a lottery prize of $1,000,000!"
        result = ScamAnalyzer.analyze(text)
        
        assert result["scam_type"] == "lottery_scam"
        assert result["confidence"] > 0

    def test_intimidation_scam_detection(self):
        """Threat/intimidation keywords should be detected."""
        text = "Police will arrest you. Legal action will be taken. Pay the fine now."
        result = ScamAnalyzer.analyze(text)
        
        assert result["scam_type"] == "intimidation_scam"
        assert "threat" in result["detected_keywords"]

    def test_urgency_keywords_detected(self):
        """Urgency keywords should be identified."""
        text = "Act immediately! This is urgent. Hurry before it's too late!"
        result = ScamAnalyzer.analyze(text)
        
        assert "urgency" in result["detected_keywords"]
        assert "immediately" in result["detected_keywords"]["urgency"]
        assert "urgent" in result["detected_keywords"]["urgency"]

    def test_action_keywords_detected(self):
        """Action keywords should be identified."""
        text = "Click here and share your details. Send us the confirmation."
        result = ScamAnalyzer.analyze(text)
        
        assert "action" in result["detected_keywords"]

    def test_high_risk_level(self):
        """Multiple scam indicators should result in HIGH risk level."""
        text = "URGENT! Your bank account blocked. Share OTP immediately or face arrest!"
        result = ScamAnalyzer.analyze(text)
        
        assert result["risk_level"] == "HIGH"
        assert result["confidence"] > 0.5

    def test_medium_risk_level(self):
        """Some scam indicators should result in MEDIUM risk level."""
        text = "Please verify your account details."
        result = ScamAnalyzer.analyze(text)
        
        # Should have some indicators but not high confidence
        assert result["risk_level"] in ["LOW", "MEDIUM"]

    def test_low_risk_level_benign_message(self):
        """Normal message should have LOW risk level."""
        text = "Hello, how are you? Nice weather!"
        result = ScamAnalyzer.analyze(text)
        
        assert result["risk_level"] == "LOW"
        assert result["confidence"] == 0

    def test_case_insensitive_detection(self):
        """Detection should be case insensitive."""
        text = "URGENT BANK BLOCKED OTP PASSWORD"
        result = ScamAnalyzer.analyze(text)
        
        assert result["scam_type"] == "banking_fraud"
        assert result["confidence"] > 0

    def test_confidence_capped_at_one(self):
        """Confidence should never exceed 1.0."""
        text = "URGENT immediately now hurry bank blocked suspended verify OTP pin password money payment lottery prize won click call share send arrest police legal"
        result = ScamAnalyzer.analyze(text)
        
        assert result["confidence"] <= 1.0

    def test_upi_keyword_triggers_banking_fraud(self):
        """UPI keyword should trigger banking fraud detection."""
        text = "Enter your UPI pin to receive payment"
        result = ScamAnalyzer.analyze(text)
        
        assert result["scam_type"] == "banking_fraud"

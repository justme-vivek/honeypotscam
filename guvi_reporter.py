import os
import json
import logging
import requests
import sqlite3
import threading
from typing import Dict, Optional
from dotenv import load_dotenv

# ============================================================================
# SETUP & CONFIGURATION
# ============================================================================

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("GuviReporter")

# GUVI Callback Configuration
GUVI_CALLBACK_URL = os.getenv("EVAL_ENDPOINT", "https://hackathon.guvi.in/api/updateHoneyPotFinalResult")
GUVI_CALLBACK_ENABLED = True  # Set to True to enable pushing to GUVI

# Database paths (imported from db_manager for consistency)
SCAM_SESSION_DB = "scam_session.db"

# ============================================================================
# GUVI REPORTER CLASS
# ============================================================================

class GuviReporter:
    """Handles all GUVI callback functionality for scam intelligence reporting."""

    def __init__(self):
        self.lock = threading.Lock()

    def is_enabled(self) -> bool:
        """Check if GUVI callback is enabled."""
        return GUVI_CALLBACK_ENABLED

    def get_guvi_payload(self, session_id: str) -> Optional[Dict]:
        """
        Get GUVI callback payload format for a scam session.

        Args:
            session_id: The session ID to get payload for

        Returns:
            Dict containing the GUVI payload format, or None if not found
        """
        with self.lock:
            try:
                conn = sqlite3.connect(SCAM_SESSION_DB)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                cursor.execute("SELECT * FROM scam_intelligence WHERE session_id = ?", (session_id,))
                row = cursor.fetchone()
                conn.close()

                if not row:
                    logger.warning(f"No scam intelligence found for session {session_id}")
                    return None

                return {
                    "scamDetected": True,
                    "totalMessagesExchanged": row["total_messages_exchanged"],
                    "extractedIntelligence": {
                        "bankAccounts": json.loads(row["bank_accounts"]),
                        "upiIds": json.loads(row["upi_ids"]),
                        "phishingLinks": json.loads(row["phishing_links"]),
                        "phoneNumbers": json.loads(row["phone_numbers"]),
                        "suspiciousKeywords": json.loads(row["suspicious_keywords"])
                    },
                    "agentNotes": row["agent_notes"]
                }
            except Exception as e:
                logger.error(f"Error getting GUVI payload for {session_id}: {e}")
                return None

    def push_to_guvi(self, session_id: str) -> bool:
        """
        Push scam intelligence to GUVI evaluation endpoint.

        Args:
            session_id: The session ID to push

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_enabled():
            logger.info(f"📤 GUVI callback disabled, skipping push for {session_id}")
            return False

        payload = self.get_guvi_payload(session_id)

        if not payload:
            logger.error(f"❌ No payload found for session {session_id}")
            return False

        try:
            logger.info(f"📤 Pushing to GUVI: {session_id}")
            response = requests.post(
                GUVI_CALLBACK_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            if response.status_code == 200:
                self.mark_pushed_to_guvi(session_id)
                logger.info(f"✅ Successfully pushed {session_id} to GUVI")
                return True
            else:
                logger.error(f"❌ GUVI push failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"❌ GUVI callback error: {e}")
            return False

    def mark_pushed_to_guvi(self, session_id: str):
        """
        Mark a scam session as pushed to GUVI.

        Args:
            session_id: The session ID to mark as pushed
        """
        with self.lock:
            try:
                conn = sqlite3.connect(SCAM_SESSION_DB)
                cursor = conn.cursor()

                cursor.execute("""
                    UPDATE scam_intelligence
                    SET pushed_to_guvi = 1, pushed_at = CURRENT_TIMESTAMP
                    WHERE session_id = ?
                """, (session_id,))

                conn.commit()
                conn.close()
                logger.info(f"✅ Marked {session_id} as pushed to GUVI")
            except Exception as e:
                logger.error(f"Error marking {session_id} as pushed: {e}")

    def push_all_pending_to_guvi(self) -> Dict:
        """
        Push all pending scam sessions to GUVI.

        Returns:
            Dict containing statistics about the push operation
        """
        if not self.is_enabled():
            return {"enabled": False, "message": "GUVI callback is disabled"}

        with self.lock:
            try:
                conn = sqlite3.connect(SCAM_SESSION_DB)
                cursor = conn.cursor()

                cursor.execute("SELECT session_id FROM scam_intelligence WHERE pushed_to_guvi = 0")
                pending = [row[0] for row in cursor.fetchall()]
                conn.close()
            except Exception as e:
                logger.error(f"Error getting pending sessions: {e}")
                return {"enabled": True, "error": str(e)}

        success = 0
        failed = 0

        for session_id in pending:
            if self.push_to_guvi(session_id):
                success += 1
            else:
                failed += 1

        result = {
            "enabled": True,
            "total_pending": len(pending),
            "success": success,
            "failed": failed
        }

        logger.info(f"📊 GUVI push summary: {result}")
        return result

    def push_direct_to_guvi(self, payload: Dict) -> bool:
        """
        Push intelligence payload directly to GUVI without requiring scam_session.db.
        
        Args:
            payload: Dict in GUVI format with scamDetected, totalMessagesExchanged, etc.
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_enabled():
            logger.info("📤 GUVI callback disabled, skipping direct push")
            return False
        
        try:
            logger.info(f"📤 Pushing directly to GUVI: {json.dumps(payload)[:200]}...")
            response = requests.post(
                GUVI_CALLBACK_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"✅ Successfully pushed to GUVI")
                return True
            else:
                logger.error(f"❌ GUVI push failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"❌ GUVI callback error: {e}")
            return False

    def get_pending_sessions_count(self) -> int:
        """
        Get the count of scam sessions that haven't been pushed to GUVI yet.

        Returns:
            int: Number of pending sessions
        """
        if not self.is_enabled():
            return 0

        with self.lock:
            try:
                conn = sqlite3.connect(SCAM_SESSION_DB)
                cursor = conn.cursor()

                cursor.execute("SELECT COUNT(*) FROM scam_intelligence WHERE pushed_to_guvi = 0")
                count = cursor.fetchone()[0]
                conn.close()

                return count
            except Exception as e:
                logger.error(f"Error getting pending count: {e}")
                return 0

# ============================================================================
# GLOBAL INSTANCE
# ============================================================================

guvi_reporter = GuviReporter()

# ============================================================================
# TEST FUNCTION
# ============================================================================

if __name__ == "__main__":
    print("GUVI Reporter Status:")
    print(f"Enabled: {guvi_reporter.is_enabled()}")
    print(f"Pending sessions: {guvi_reporter.get_pending_sessions_count()}")

    if guvi_reporter.is_enabled():
        print("Testing GUVI push functionality...")
        stats = guvi_reporter.push_all_pending_to_guvi()
        print(f"Push stats: {stats}")
    else:
        print("GUVI callback is disabled. Set GUVI_CALLBACK_ENABLED = True to test.")
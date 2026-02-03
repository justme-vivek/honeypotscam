"""
Database Manager for Honeypot Scam Detection System
====================================================
Manages 3 databases:
1. current_session.db - Active session being processed
2. chat_sessions.db   - Archive of ALL completed sessions
3. scam_sessions.db   - Extracted intelligence from confirmed scams (for GUVI callback)
"""

import sqlite3
import json
import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DBManager")

# ============================================================================
# DATABASE PATHS
# ============================================================================

CURRENT_SESSION_DB = "current_session.db"
CHAT_SESSIONS_DB = "chat_sessions.db"
SCAM_SESSION_DB = "scam_session.db"  # Renamed from scam_sessions.db

# Session timeout in seconds (5 minutes)
SESSION_TIMEOUT_SECONDS = 300

# GUVI Callback endpoint (disabled for now)
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
GUVI_CALLBACK_ENABLED = False  # Set to True to enable pushing to GUVI

# ============================================================================
# DATABASE MANAGER CLASS
# ============================================================================

class DatabaseManager:
    """Unified manager for all 3 databases."""
    
    def __init__(self):
        self.lock = threading.Lock()
        self._init_all_databases()
    
    def _init_all_databases(self):
        """Initialize all 3 database schemas."""
        self._init_current_session_db()
        self._init_chat_sessions_db()
        self._init_scam_session_db()
        logger.info("✅ All databases initialized")
    
    # ========================================================================
    # 1. CURRENT SESSION DB (Active/Working Session)
    # ========================================================================
    
    def _init_current_session_db(self):
        """Create current_session.db schema."""
        with self.lock:
            conn = sqlite3.connect(CURRENT_SESSION_DB)
            cursor = conn.cursor()
            
            # Session info table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS session_info (
                    session_id TEXT PRIMARY KEY,
                    channel TEXT DEFAULT 'SMS',
                    language TEXT DEFAULT 'English',
                    locale TEXT DEFAULT 'IN',
                    scam_flags INTEGER DEFAULT 0,
                    is_confirmed_scam BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Messages table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    text TEXT NOT NULL,
                    timestamp TEXT,
                    is_response BOOLEAN DEFAULT 0,
                    is_scam_flag BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Running intelligence extraction
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS extracted_intel (
                    session_id TEXT PRIMARY KEY,
                    bank_accounts TEXT DEFAULT '[]',
                    upi_ids TEXT DEFAULT '[]',
                    phishing_links TEXT DEFAULT '[]',
                    phone_numbers TEXT DEFAULT '[]',
                    suspicious_keywords TEXT DEFAULT '[]',
                    agent_notes TEXT DEFAULT '',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
            conn.close()
    
    def save_to_current_session(
        self,
        session_id: str,
        sender: str,
        text: str,
        is_response: bool = False,
        is_scam_flag: bool = False,
        metadata: Optional[Dict] = None
    ):
        """Save a message to current session."""
        with self.lock:
            conn = sqlite3.connect(CURRENT_SESSION_DB)
            cursor = conn.cursor()
            
            # Create or update session info
            cursor.execute("""
                INSERT INTO session_info (session_id, channel, language, locale, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(session_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP
            """, (
                session_id,
                metadata.get("channel", "SMS") if metadata else "SMS",
                metadata.get("language", "English") if metadata else "English",
                metadata.get("locale", "IN") if metadata else "IN"
            ))
            
            # Save message
            cursor.execute("""
                INSERT INTO messages (session_id, sender, text, timestamp, is_response, is_scam_flag)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                sender,
                text,
                datetime.now().isoformat(),
                1 if is_response else 0,
                1 if is_scam_flag else 0
            ))
            
            # Increment scam flag counter if this message is flagged
            if is_scam_flag:
                cursor.execute("""
                    UPDATE session_info 
                    SET scam_flags = scam_flags + 1,
                        is_confirmed_scam = CASE WHEN scam_flags + 1 >= 2 THEN 1 ELSE 0 END
                    WHERE session_id = ?
                """, (session_id,))
            
            conn.commit()
            conn.close()
    
    def update_extracted_intel(self, session_id: str, intelligence: Dict):
        """Update extracted intelligence for current session."""
        with self.lock:
            conn = sqlite3.connect(CURRENT_SESSION_DB)
            cursor = conn.cursor()
            
            extracted = intelligence.get("extractedIntelligence", {})
            
            cursor.execute("""
                INSERT INTO extracted_intel (
                    session_id, bank_accounts, upi_ids, phishing_links, 
                    phone_numbers, suspicious_keywords, agent_notes, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(session_id) DO UPDATE SET
                    bank_accounts = ?,
                    upi_ids = ?,
                    phishing_links = ?,
                    phone_numbers = ?,
                    suspicious_keywords = ?,
                    agent_notes = ?,
                    updated_at = CURRENT_TIMESTAMP
            """, (
                session_id,
                json.dumps(extracted.get("bankAccounts", [])),
                json.dumps(extracted.get("upiIds", [])),
                json.dumps(extracted.get("phishingLinks", [])),
                json.dumps(extracted.get("phoneNumbers", [])),
                json.dumps(extracted.get("suspiciousKeywords", [])),
                intelligence.get("agentNotes", ""),
                # For UPDATE
                json.dumps(extracted.get("bankAccounts", [])),
                json.dumps(extracted.get("upiIds", [])),
                json.dumps(extracted.get("phishingLinks", [])),
                json.dumps(extracted.get("phoneNumbers", [])),
                json.dumps(extracted.get("suspiciousKeywords", [])),
                intelligence.get("agentNotes", "")
            ))
            
            conn.commit()
            conn.close()
    
    def get_session_scam_status(self, session_id: str) -> Dict:
        """Get current scam status for a session."""
        with self.lock:
            conn = sqlite3.connect(CURRENT_SESSION_DB)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT scam_flags, is_confirmed_scam FROM session_info WHERE session_id = ?
            """, (session_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {"scam_flags": row[0], "is_confirmed_scam": bool(row[1])}
            return {"scam_flags": 0, "is_confirmed_scam": False}
    
    def get_current_session_data(self, session_id: str) -> Optional[Dict]:
        """Get all data for a session from current_session.db."""
        with self.lock:
            conn = sqlite3.connect(CURRENT_SESSION_DB)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get session info
            cursor.execute("SELECT * FROM session_info WHERE session_id = ?", (session_id,))
            session_row = cursor.fetchone()
            
            if not session_row:
                conn.close()
                return None
            
            session_info = dict(session_row)
            
            # Get messages
            cursor.execute("""
                SELECT * FROM messages WHERE session_id = ? ORDER BY id
            """, (session_id,))
            messages = [dict(row) for row in cursor.fetchall()]
            
            # Get extracted intelligence
            cursor.execute("SELECT * FROM extracted_intel WHERE session_id = ?", (session_id,))
            intel_row = cursor.fetchone()
            intel = dict(intel_row) if intel_row else None
            
            conn.close()
            
            return {
                "session_info": session_info,
                "messages": messages,
                "extracted_intel": intel
            }
    
    # ========================================================================
    # 2. CHAT SESSIONS DB (Archive of ALL Sessions)
    # ========================================================================
    
    def _init_chat_sessions_db(self):
        """Create chat_sessions.db schema."""
        with self.lock:
            conn = sqlite3.connect(CHAT_SESSIONS_DB)
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    channel TEXT,
                    language TEXT,
                    locale TEXT,
                    total_messages INTEGER DEFAULT 0,
                    is_scam BOOLEAN DEFAULT 0,
                    scam_flags_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP,
                    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    text TEXT NOT NULL,
                    timestamp TEXT,
                    is_response BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP
                )
            """)
            
            conn.commit()
            conn.close()
    
    def archive_to_chat_sessions(self, session_id: str, session_data: Dict):
        """Archive a completed session to chat_sessions.db."""
        with self.lock:
            conn = sqlite3.connect(CHAT_SESSIONS_DB)
            cursor = conn.cursor()
            
            session_info = session_data["session_info"]
            messages = session_data["messages"]
            
            # Insert session
            cursor.execute("""
                INSERT OR REPLACE INTO sessions (
                    session_id, channel, language, locale, total_messages,
                    is_scam, scam_flags_count, created_at, completed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                session_id,
                session_info.get("channel", "SMS"),
                session_info.get("language", "English"),
                session_info.get("locale", "IN"),
                len(messages),
                session_info.get("is_confirmed_scam", 0),
                session_info.get("scam_flags", 0),
                session_info.get("created_at")
            ))
            
            # Insert messages
            for msg in messages:
                cursor.execute("""
                    INSERT INTO messages (session_id, sender, text, timestamp, is_response, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    session_id,
                    msg.get("sender"),
                    msg.get("text"),
                    msg.get("timestamp"),
                    msg.get("is_response", 0),
                    msg.get("created_at")
                ))
            
            conn.commit()
            conn.close()
            logger.info(f"📦 Session {session_id} archived to chat_sessions.db")
    
    # ========================================================================
    # 3. SCAM SESSIONS DB (GUVI Callback Data - Scams Only)
    # ========================================================================
    
    def _init_scam_session_db(self):
        """Create scam_session.db schema."""
        with self.lock:
            conn = sqlite3.connect(SCAM_SESSION_DB)
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scam_intelligence (
                    session_id TEXT PRIMARY KEY,
                    scam_detected BOOLEAN DEFAULT 1,
                    total_messages_exchanged INTEGER DEFAULT 0,
                    bank_accounts TEXT DEFAULT '[]',
                    upi_ids TEXT DEFAULT '[]',
                    phishing_links TEXT DEFAULT '[]',
                    phone_numbers TEXT DEFAULT '[]',
                    suspicious_keywords TEXT DEFAULT '[]',
                    agent_notes TEXT DEFAULT '',
                    pushed_to_guvi BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    pushed_at TIMESTAMP
                )
            """)
            
            conn.commit()
            conn.close()
    
    def save_to_scam_session(self, session_id: str, session_data: Dict):
        """Save confirmed scam intelligence to scam_session.db."""
        with self.lock:
            conn = sqlite3.connect(SCAM_SESSION_DB)
            cursor = conn.cursor()
            
            intel = session_data.get("extracted_intel", {})
            messages = session_data.get("messages", [])
            
            cursor.execute("""
                INSERT OR REPLACE INTO scam_intelligence (
                    session_id, scam_detected, total_messages_exchanged,
                    bank_accounts, upi_ids, phishing_links, phone_numbers,
                    suspicious_keywords, agent_notes, created_at
                )
                VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                session_id,
                len(messages),
                intel.get("bank_accounts", "[]") if intel else "[]",
                intel.get("upi_ids", "[]") if intel else "[]",
                intel.get("phishing_links", "[]") if intel else "[]",
                intel.get("phone_numbers", "[]") if intel else "[]",
                intel.get("suspicious_keywords", "[]") if intel else "[]",
                intel.get("agent_notes", "") if intel else ""
            ))
            
            conn.commit()
            conn.close()
            logger.info(f"🚨 Scam session {session_id} saved to scam_session.db")
    
    def get_guvi_payload(self, session_id: str) -> Optional[Dict]:
        """Get GUVI callback payload format for a scam session."""
        with self.lock:
            conn = sqlite3.connect(SCAM_SESSION_DB)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM scam_intelligence WHERE session_id = ?", (session_id,))
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return None
            
            return {
                "sessionId": session_id,
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
    
    def mark_pushed_to_guvi(self, session_id: str):
        """Mark a scam session as pushed to GUVI."""
        with self.lock:
            conn = sqlite3.connect(SCAM_SESSION_DB)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE scam_intelligence 
                SET pushed_to_guvi = 1, pushed_at = CURRENT_TIMESTAMP
                WHERE session_id = ?
            """, (session_id,))
            
            conn.commit()
            conn.close()
    
    # ========================================================================
    # SESSION FINALIZATION (Move from current → archive/scam)
    # ========================================================================
    
    def finalize_session(self, session_id: str):
        """
        Finalize a session:
        1. Get data from current_session.db
        2. If confirmed scam (2+ flags): save to scam_sessions.db
        3. Archive to chat_sessions.db (all sessions)
        4. Clear from current_session.db
        """
        session_data = self.get_current_session_data(session_id)
        
        if not session_data:
            logger.warning(f"⚠️ Session {session_id} not found in current_session.db")
            return False
        
        is_scam = session_data["session_info"].get("is_confirmed_scam", False)
        
        # If confirmed scam, save to scam_session.db
        if is_scam:
            self.save_to_scam_session(session_id, session_data)
            
            # Try to push to GUVI if enabled
            if GUVI_CALLBACK_ENABLED:
                self.push_to_guvi(session_id)
        
        # Archive to chat_sessions.db (ALL sessions go here)
        self.archive_to_chat_sessions(session_id, session_data)
        
        # Clear from current_session.db
        self.clear_current_session(session_id)
        
        logger.info(f"✅ Session {session_id} finalized (scam={is_scam})")
        return True
    
    def clear_current_session(self, session_id: str):
        """Remove a session from current_session.db after archiving."""
        with self.lock:
            conn = sqlite3.connect(CURRENT_SESSION_DB)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
            cursor.execute("DELETE FROM extracted_intel WHERE session_id = ?", (session_id,))
            cursor.execute("DELETE FROM session_info WHERE session_id = ?", (session_id,))
            
            conn.commit()
            conn.close()
            logger.info(f"🗑️ Session {session_id} cleared from current_session.db")
    
    def clear_all_current_sessions(self):
        """Clear ALL data from current_session.db."""
        with self.lock:
            conn = sqlite3.connect(CURRENT_SESSION_DB)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM messages")
            cursor.execute("DELETE FROM extracted_intel")
            cursor.execute("DELETE FROM session_info")
            
            conn.commit()
            conn.close()
            logger.info("🗑️ All current sessions cleared")
    
    # ========================================================================
    # TIMEOUT-BASED SESSION COMPLETION
    # ========================================================================
    
    def get_timed_out_sessions(self) -> List[str]:
        """Get list of sessions that have timed out (no activity for SESSION_TIMEOUT_SECONDS)."""
        with self.lock:
            conn = sqlite3.connect(CURRENT_SESSION_DB)
            cursor = conn.cursor()
            
            # Get sessions where updated_at is older than timeout
            cursor.execute("""
                SELECT session_id FROM session_info 
                WHERE datetime(updated_at) < datetime('now', ? || ' seconds')
            """, (f"-{SESSION_TIMEOUT_SECONDS}",))
            
            timed_out = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            return timed_out
    
    def finalize_timed_out_sessions(self) -> int:
        """Finalize all timed-out sessions. Returns count of finalized sessions."""
        timed_out = self.get_timed_out_sessions()
        
        for session_id in timed_out:
            logger.info(f"⏰ Session {session_id} timed out, finalizing...")
            self.finalize_session(session_id)
        
        return len(timed_out)
    
    # ========================================================================
    # GUVI CALLBACK (Disabled by default)
    # ========================================================================
    
    def push_to_guvi(self, session_id: str) -> bool:
        """
        Push scam intelligence to GUVI evaluation endpoint.
        Only called if GUVI_CALLBACK_ENABLED = True
        
        Endpoint: POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult
        """
        import requests
        
        if not GUVI_CALLBACK_ENABLED:
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
    
    def push_all_pending_to_guvi(self) -> Dict:
        """Push all pending scam sessions to GUVI. Returns stats."""
        if not GUVI_CALLBACK_ENABLED:
            return {"enabled": False, "message": "GUVI callback is disabled"}
        
        with self.lock:
            conn = sqlite3.connect(SCAM_SESSION_DB)
            cursor = conn.cursor()
            
            cursor.execute("SELECT session_id FROM scam_intelligence WHERE pushed_to_guvi = 0")
            pending = [row[0] for row in cursor.fetchall()]
            conn.close()
        
        success = 0
        failed = 0
        
        for session_id in pending:
            if self.push_to_guvi(session_id):
                success += 1
            else:
                failed += 1
        
        return {
            "enabled": True,
            "total_pending": len(pending),
            "success": success,
            "failed": failed
        }


# ============================================================================
# SINGLETON INSTANCE
# ============================================================================

db_manager = DatabaseManager()

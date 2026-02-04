"""
Honeypot Scam Detection API
Handles scammer messages and generates engaging responses to waste their time.

Usage:
  python app.py
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn
import json
import hashlib
import time
import sqlite3
import threading
import random
from datetime import datetime
from typing import Optional, List, Dict, Any
import logging
import os
from dotenv import load_dotenv
from gemma_responder import process_incoming_message
from db_manager import db_manager
from guvi_reporter import GuviReporter




# Load environment variables
load_dotenv()

# ============================================================================
# LOGGING SETUP
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

API_KEY = os.getenv("x-api-key")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

if ENVIRONMENT == "development":
    logger.warning(f"⚠️  Using API_KEY: {API_KEY}")

# ============================================================================
# DATA MODELS - Flexible Format
# ============================================================================

class Message(BaseModel):
    """Single message in conversation"""
    sender: str = Field(default="scammer", description="'scammer' or 'user'")
    text: str = Field(default="", description="Message content")
    timestamp: Optional[str] = Field(default=None, description="ISO-8601 format timestamp")

class Metadata(BaseModel):
    """Request metadata"""
    channel: Optional[str] = Field(default="SMS", description="SMS / WhatsApp / Email / Chat")
    language: Optional[str] = Field(default="English", description="Language used")
    locale: Optional[str] = Field(default="IN", description="Country or region")

class ScamRequest(BaseModel):
    """Incoming scam detection request - ALL FIELDS OPTIONAL"""
    sessionId: Optional[str] = Field(default=None, description="Unique session identifier")
    message: Optional[Message] = Field(default=None, description="Latest incoming message")
    conversationHistory: Optional[List[Message]] = Field(default=[], description="Previous messages")
    metadata: Optional[Metadata] = Field(default=None, description="Optional metadata")
    
    model_config = {"extra": "allow"}

class ScamResponse(BaseModel):
    """Response to scam message"""
    sessionId: str
    honeypot_response: Optional[str] = Field(default=None, description="Simple text response for display")
    response: Message
    analysis: Dict = Field(default={})
    status: str = Field(default="success")
    
    model_config = {"extra": "allow"}

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    service: str
    version: str

# ============================================================================
# AUTHENTICATION
# ============================================================================

class APIKeyVerifier:
    """Verify API key from request headers"""
    
    @staticmethod
    def verify(request: Request) -> bool:
        api_key = request.headers.get("x-api-key")
        
        if not api_key:
            logger.warning("🔴 Request without API key")
            raise HTTPException(
                status_code=401,
                detail="Missing x-api-key header"
            )
        
        if api_key != API_KEY:
            logger.warning(f"🔴 Invalid API key: {api_key[:10]}...")
            raise HTTPException(
                status_code=401,
                detail="Invalid API key"
            )
        
        return True

# ============================================================================
# DATABASE SETUP
# ============================================================================

class Database:
    """SQLite database manager"""
    
    def __init__(self, db_path: str = "scam_session.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_db()
    
    def init_db(self):
        """Create tables if they don't exist"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    channel TEXT,
                    language TEXT,
                    locale TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
            conn.close()
            logger.info("✅ Database initialized")
    
    def save_session(self, session_id: str, metadata: Metadata = None):
        """Save or update session"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO sessions (session_id, channel, language, locale, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (session_id, 
                  metadata.channel if metadata else "SMS",
                  metadata.language if metadata else "English",
                  metadata.locale if metadata else "IN"))
            
            conn.commit()
            conn.close()
    
    def save_message(self, session_id: str, sender: str, text: str, is_response: bool = False):
        """Save message to database"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO messages (session_id, sender, text, timestamp, is_response)
                VALUES (?, ?, ?, ?, ?)
            """, (session_id, sender, text, datetime.utcnow().isoformat(), is_response))
            
            conn.commit()
            conn.close()

db = Database()

# ============================================================================
# SCAM ANALYZER
# ============================================================================

class ScamAnalyzer:
    """Analyze messages for scam patterns"""
    
    SCAM_KEYWORDS = {
        "urgency": ["immediately", "urgent", "today", "now", "hurry", "fast", "quick", "limited time"],
        "banking": ["bank", "account", "blocked", "suspended", "verify", "upi", "otp", "pin", "password"],
        "money": ["money", "payment", "transfer", "cash", "lottery", "prize", "won", "reward"],
        "threat": ["blocked", "suspended", "legal", "police", "arrest", "court", "fine"],
        "action": ["click", "call", "share", "send", "provide", "confirm", "update"]
    }
    
    @classmethod
    def analyze(cls, text: str) -> Dict:
        """Analyze text for scam indicators"""
        if not text:
            return {"scam_type": "unknown", "confidence": 0, "detected_keywords": {}, "risk_level": "LOW"}
        
        text_lower = text.lower()
        
        detected_keywords = {}
        total_score = 0
        
        for category, keywords in cls.SCAM_KEYWORDS.items():
            found = [kw for kw in keywords if kw in text_lower]
            if found:
                detected_keywords[category] = found
                total_score += len(found) * 10
        
        scam_type = "unknown"
        if "banking" in detected_keywords or "upi" in text_lower:
            scam_type = "banking_fraud"
        elif "lottery" in text_lower or "prize" in text_lower or "won" in text_lower:
            scam_type = "lottery_scam"
        elif "threat" in detected_keywords:
            scam_type = "intimidation_scam"
        elif total_score > 0:
            scam_type = "generic_scam"
        
        confidence = min(total_score / 100, 1.0)
        
        return {
            "scam_type": scam_type,
            "confidence": round(confidence, 2),
            "detected_keywords": detected_keywords,
            "risk_level": "HIGH" if confidence > 0.5 else "MEDIUM" if confidence > 0.2 else "LOW"
        }

# ============================================================================
# RESPONSE GENERATOR (Honeypot)
# ============================================================================

class HoneypotResponder:
    """Generate responses to keep scammers engaged"""
    
    RESPONSES = [
        "I don't understand. What bank account?",
        "Sorry, can you explain more clearly?",
        "Which account are you talking about?",
        "I have multiple accounts. Which one?",
        "My grandson usually handles these things for me.",
        "Wait, let me get my reading glasses first.",
        "Oh no! What should I do?",
        "Please help me! I don't want my account blocked!",
        "I'm scared. What information do you need?",
        "My pension money is in that account!",
        "Let me find my documents. One moment please.",
        "Hold on, someone is at the door...",
        "Wait, my phone is dying. Let me find the charger.",
        "Can you hold? I need to find my reading glasses.",
        "What company did you say you're from?",
        "Can you give me your employee ID?",
        "What's your callback number?",
    ]
    
    @classmethod
    def generate_response(cls, history_length: int = 0) -> str:
        """Generate an engaging response"""
        return random.choice(cls.RESPONSES)

# ============================================================================
# METRICS
# ============================================================================

class Metrics:
    def __init__(self):
        self.requests_received = 0
        self.scams_detected = 0
        self.sessions_active = set()
        self.start_time = datetime.utcnow()
    
    def get_stats(self) -> dict:
        uptime = datetime.utcnow() - self.start_time
        return {
            "requests_received": self.requests_received,
            "scams_detected": self.scams_detected,
            "active_sessions": len(self.sessions_active),
            "uptime_seconds": uptime.total_seconds()
        }

metrics = Metrics()

# ============================================================================
# BACKGROUND TASK: Session Timeout Checker
# ============================================================================

import asyncio

async def session_timeout_checker():
    """Background task to finalize timed-out sessions every 60 seconds."""
    while True:
        try:
            await asyncio.sleep(60)  # Check every 60 seconds
            count = db_manager.finalize_timed_out_sessions()
            if count > 0:
                logger.info(f"⏰ Finalized {count} timed-out session(s)")
        except Exception as e:
            logger.error(f"Error in timeout checker: {e}")

# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Honeypot Scam Detection API",
    description="Detects scam messages and generates responses to waste scammers' time",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

@app.on_event("startup")
async def startup_event():
    """Start background tasks on app startup."""
    asyncio.create_task(session_timeout_checker())
    logger.info("🚀 Session timeout checker started (checking every 60s)")

# Add CORS middleware to allow browser requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Debug Middleware to see what the platform sends
@app.middleware("http")
async def log_request_body(request: Request, call_next):
    try:
        body = await request.body()
        if body:
            logger.info(f"🔍 DEBUG RAW BODY: {body.decode('utf-8', errors='ignore')}")
        else:
            logger.info("🔍 DEBUG RAW BODY: <EMPTY>")
        
        # Reset stream for next consumer
        async def receive():
            return {"type": "http.request", "body": body}
        request._receive = receive
    except Exception as e:
        logger.error(f"Error reading body in middleware: {e}")
    
    response = await call_next(request)
    return response

# ============================================================================
# ENDPOINTS
# ============================================================================

@app.post("/api/chat")
async def handle_scam_message(request: Request):
    """
    Process incoming scam message and generate honeypot response.
    Accepts ANY JSON format flexibly.
    
    REQUIRES: x-api-key header
    """
    # Verify API key
    APIKeyVerifier.verify(request)
    
    processing_start = time.time()
    metrics.requests_received += 1
    
    try:
        # Get raw body safe handling
        try:
            body = await request.json()
            if not body:
                body = {}
        except Exception:
            # Maybe it's not JSON? Try query params if body failed
            body = dict(request.query_params)
            logger.info(f"Using query params as fallback: {body}")

        logger.info(f"📥 Received parsed request: {json.dumps(body)[:200]}...")
        
        # Extract data flexibly
        session_id = body.get("sessionId") or body.get("session_id") or f"session_{int(time.time()*1000)}"
        
        # Get message text from various possible formats
        message_text = ""
        # 1. Standard Object
        if isinstance(body.get("message"), dict):
            message_text = body["message"].get("text", "")
        # 2. String field
        elif isinstance(body.get("message"), str):
            message_text = body["message"]
        # 3. Direct 'text' field
        elif body.get("text"):
            message_text = body["text"]
        # 4. 'content' field
        elif body.get("content"):
            message_text = body["content"]
        
        # If still empty, use a placeholder to avoid empty prompt error - but allow logic to proceed
        if not message_text:
            logger.warning("Empty message text received!")
            message_text = "Hello" # Fallback to trigger a response even if input is empty
        
        # Get sender
        sender = "scammer"
        if isinstance(body.get("message"), dict):
            sender = body["message"].get("sender", "scammer")
        
        # Get history length
        history = body.get("conversationHistory", [])
        history_length = len(history) if isinstance(history, list) else 0
        
        # Track session
        metrics.sessions_active.add(session_id)
        
        # Get metadata dict
        metadata_dict = None
        if body.get("metadata"):
            metadata_dict = body["metadata"]
        
        # Analyze for scam patterns FIRST
        analysis = ScamAnalyzer.analyze(message_text)
        is_scam_flag = analysis["confidence"] > 0.3  # Flag if confidence > 30%
        
        if is_scam_flag:
            metrics.scams_detected += 1
        
        # Save incoming message to current_session.db
        db_manager.save_to_current_session(
            session_id=session_id,
            sender=sender,
            text=message_text,
            is_response=False,
            is_scam_flag=is_scam_flag,
            metadata=metadata_dict
        )
        
        # Generate honeypot response with intelligence extraction
        result = process_incoming_message(
            current_message=message_text,
            conversation_history=history,
            session_id=session_id
        )
        
        response_text = result.get("reply", "")
        intelligence = result.get("intelligence", {})
        
        # Ensure response_text is not empty or None
        if not response_text or not response_text.strip():
            response_text = "Sorry sir, network issue. Can you repeat?"
        
        # Save our response to current_session.db
        db_manager.save_to_current_session(
            session_id=session_id,
            sender="user",
            text=response_text,
            is_response=True,
            is_scam_flag=False,
            metadata=metadata_dict
        )
        
        # Update extracted intelligence
        if intelligence:
            db_manager.update_extracted_intel(session_id, intelligence)
        
        # Check if session is now confirmed scam (2+ flags)
        scam_status = db_manager.get_session_scam_status(session_id)
        if scam_status["is_confirmed_scam"]:
            logger.info(f"🚨 Session {session_id} CONFIRMED as SCAM ({scam_status['scam_flags']} flags)")
        
        latency_ms = (time.time() - processing_start) * 1000
        logger.info(f"✅ Session {session_id} processed in {latency_ms:.2f}ms")
        
        # Return response matching problem statement format exactly:
        # { "status": "success", "reply": "message text" }
        
        content = {
            "status": "success",
            "reply": response_text
        }

        return JSONResponse(content=content, headers={"Access-Control-Allow-Origin": "*"})
    
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        return JSONResponse(
            status_code=400, 
            content={"status": "error", "reply": "Invalid JSON format"},
            headers={"Access-Control-Allow-Origin": "*"}
        )
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        return JSONResponse(
            status_code=500, 
            content={"status": "error", "reply": str(e)},
            headers={"Access-Control-Allow-Origin": "*"}
        )

@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint (NO authentication required)"""
    return {
        "status": "healthy",
        "service": "honeypot-scam-api",
        "version": "1.0.0"
    }

@app.get("/ping")
async def ping():
    """Simple ping endpoint for keep-alive services (NO authentication required)."""
    return {"status": "pong", "timestamp": datetime.utcnow().isoformat()}

@app.get("/metrics")
async def get_metrics(request: Request):
    """Get service metrics (REQUIRES x-api-key header)"""
    APIKeyVerifier.verify(request)
    return metrics.get_stats()

@app.get("/api/view-db/{db_type}")
async def view_database(db_type: str, request: Request):
    """
    View database contents as JSON for the web panel.
    db_type: 'current', 'archive', 'scams', or 'all'
    REQUIRES: x-api-key header
    """
    APIKeyVerifier.verify(request)
    
    import sqlite3
    import json as json_module
    
    result = {}
    
    def get_table_data(db_path, tables):
        data = {}
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            for table in tables:
                try:
                    cursor.execute(f"SELECT * FROM {table} ORDER BY rowid DESC LIMIT 50")
                    rows = cursor.fetchall()
                    data[table] = [dict(row) for row in rows]
                except:
                    data[table] = []
            conn.close()
        except Exception as e:
            data["error"] = str(e)
        return data
    
    if db_type in ['current', 'all']:
        result['current_session'] = get_table_data(
            'current_session.db', 
            ['session_info', 'messages', 'extracted_intel']
        )
    
    if db_type in ['archive', 'all']:
        result['chat_sessions'] = get_table_data(
            'chat_sessions.db',
            ['sessions', 'messages']
        )
    
    if db_type in ['scams', 'all']:
        result['scam_session'] = get_table_data(
            'scam_session.db',
            ['scam_intelligence']
        )
    
    return result

@app.post("/api/clear-all-data")
async def clear_all_data(request: Request):
    """
    DANGER: Clear ALL data from all databases.
    This permanently deletes everything and cannot be undone.

    REQUIRES: x-api-key header
    """
    APIKeyVerifier.verify(request)

    try:
        import os

        # List of database files to clear
        db_files = [
            "current_session.db",
            "chat_sessions.db",
            "scam_session.db"
        ]

        cleared_files = []
        errors = []

        for db_file in db_files:
            try:
                if os.path.exists(db_file):
                    os.remove(db_file)
                    cleared_files.append(db_file)
                    logger.warning(f"🗑️ Cleared database: {db_file}")
                else:
                    logger.info(f"Database file not found (already clear): {db_file}")
                    cleared_files.append(db_file)
            except Exception as e:
                error_msg = f"Failed to clear {db_file}: {str(e)}"
                errors.append(error_msg)
                logger.error(f"❌ {error_msg}")

        # Reset metrics
        metrics.sessions_active.clear()
        metrics.messages_total.set(0)
        metrics.scams_detected.set(0)

        if errors:
            return JSONResponse(
                status_code=207,  # Multi-status
                content={
                    "status": "partial_success",
                    "message": f"Cleared {len(cleared_files)}/{len(db_files)} databases",
                    "cleared": cleared_files,
                    "errors": errors
                }
            )
        else:
            return JSONResponse(content={
                "status": "success",
                "message": f"Successfully cleared all {len(cleared_files)} databases",
                "cleared": cleared_files
            })

    except Exception as e:
        logger.error(f"❌ Error in clear_all_data: {e}")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": f"Clear operation failed: {str(e)}"}
        )

@app.post("/api/end-session")
async def end_session(request: Request):
    """
    Finalize a session - moves data from current_session.db to archive.
    If confirmed scam (2+ flags), also saves to scam_session.db and pushes to GUVI.
    
    REQUIRES: x-api-key header
    Body: { "sessionId": "xxx" }
    """
    APIKeyVerifier.verify(request)
    
    try:
        body = await request.json()
        session_id = body.get("sessionId") or body.get("session_id")
        
        if not session_id:
            return JSONResponse(
                status_code=400,
                content={"status": "error", "message": "sessionId is required"}
            )
        
        # Get session status before finalizing
        scam_status = db_manager.get_session_scam_status(session_id)
        
        # Finalize the session (moves to archive, scam_sessions if confirmed)
        success = db_manager.finalize_session(session_id, push_to_guvi=True)
        
        if success:
            # Remove from active sessions
            metrics.sessions_active.discard(session_id)
            
            return JSONResponse(content={
                "status": "success",
                "message": f"Session {session_id} finalized",
                "was_scam": scam_status["is_confirmed_scam"],
                "scam_flags": scam_status["scam_flags"]
            })
        else:
            return JSONResponse(
                status_code=404,
                content={"status": "error", "message": f"Session {session_id} not found"}
            )
    
    except Exception as e:
        logger.error(f"Error ending session: {e}")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(e)}
        )

@app.get("/api/session-status/{session_id}")
async def get_session_status(session_id: str, request: Request):
    """
    Get current scam status for a session.
    REQUIRES: x-api-key header
    """
    APIKeyVerifier.verify(request)
    
    scam_status = db_manager.get_session_scam_status(session_id)
    session_data = db_manager.get_current_session_data(session_id)
    
    if not session_data:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "message": f"Session {session_id} not found"}
        )
    
    return {
        "status": "success",
        "sessionId": session_id,
        "scam_flags": scam_status["scam_flags"],
        "is_confirmed_scam": scam_status["is_confirmed_scam"],
        "message_count": len(session_data.get("messages", [])),
        "extracted_intel": session_data.get("extracted_intel")
    }

@app.post("/api/push-to-guvi")
async def push_to_guvi(request: Request):
    """
    Push all pending scam sessions to GUVI evaluation endpoint.
    REQUIRES: x-api-key header
    
    Note: GUVI callback is disabled by default.
    Set GUVI_CALLBACK_ENABLED = True in guvi_reporter.py to enable.
    """
    APIKeyVerifier.verify(request)
    
    guvi_reporter = GuviReporter()
    result = guvi_reporter.push_all_pending_to_guvi()
    return {"status": "success", **result}

@app.post("/api/finalize-timeout")
async def finalize_timeout_sessions(request: Request):
    """
    Manually trigger finalization of all timed-out sessions.
    REQUIRES: x-api-key header
    """
    APIKeyVerifier.verify(request)
    
    count = db_manager.finalize_timed_out_sessions()
    return {
        "status": "success",
        "finalized_count": count,
        "message": f"Finalized {count} timed-out session(s)"
    }

# ============================================================================
# STARTUP
# ============================================================================

if __name__ == "__main__":
    # Get port from environment (for Render deployment)
    port = int(os.getenv("PORT", 8000))
    
    print(f"""
╔════════════════════════════════════════════════════════════╗
║    🎣 Honeypot Scam Detection API                         ║
╚════════════════════════════════════════════════════════════╝

Server: http://localhost:{port}

🔐 AUTHENTICATION:
   Header: x-api-key
   Value: {API_KEY}

ENDPOINTS:
  POST /api/chat              - Process scam message
  POST /api/end-session       - Finalize a session manually
  POST /api/finalize-timeout  - Finalize all timed-out sessions
  POST /api/push-to-guvi      - Push pending scams to GUVI
  GET  /api/session-status/ID - Get session scam status
  GET  /health                - Health check (no auth)
  GET  /metrics               - Get metrics
  GET  /docs                  - Swagger UI

⏰ SESSION TIMEOUT: 5 minutes (auto-finalize)
📤 GUVI CALLBACK: Enabled (pushing to hackathon.guvi.in)

Documentation: http://localhost:{port}/docs
""")
    
    try:
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=port,
            log_level="info"
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")

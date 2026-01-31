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
from ollama_responder import generate_ollama_response




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
    
    def __init__(self, db_path: str = "scam_sessions.db"):
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
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Honeypot Scam Detection API",
    description="Detects scam messages and generates responses to waste scammers' time",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

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
        
        # Save session
        metrics.sessions_active.add(session_id)
        db.save_session(session_id)
        
        # Save incoming message
        if message_text:
            db.save_message(session_id, sender, message_text)
        
        # Analyze for scam patterns
        analysis = ScamAnalyzer.analyze(message_text)
        
        if analysis["confidence"] > 0.2:
            metrics.scams_detected += 1
        
        # Generate honeypot response using Ollama
        response_text = generate_ollama_response(
            current_message=message_text,
            conversation_history=history
        )
        
        # Save response
        db.save_message(session_id, "user", response_text, is_response=True)
        
        latency_ms = (time.time() - processing_start) * 1000
        logger.info(f"✅ Session {session_id} processed in {latency_ms:.2f}ms")
        
        # Return response with explicit CORS headers
        # Permissive Response Schema:
        # 1. 'message' field as Object (primary standard)
        # 2. 'text' and 'reply' as String fallbacks
        
        response_obj = {
            "sender": "assistant",
            "text": response_text,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        content = {
            "sessionId": session_id,
            "message": response_obj,      # Matches Message object schema
            "response": response_obj,     # Legacy support
            "text": response_text,        # Fallback string
            "reply": response_text,       # Fallback string 
            "analysis": analysis,
            "status": "success"
        }

        return JSONResponse(content=content, headers={"Access-Control-Allow-Origin": "*"})
    
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        return JSONResponse(
            status_code=400, 
            content={"detail": "Invalid JSON format"},
            headers={"Access-Control-Allow-Origin": "*"}
        )
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        return JSONResponse(
            status_code=500, 
            content={"detail": str(e)},
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

@app.get("/metrics")
async def get_metrics(request: Request):
    """Get service metrics (REQUIRES x-api-key header)"""
    APIKeyVerifier.verify(request)
    return metrics.get_stats()

# ============================================================================
# STARTUP
# ============================================================================

if __name__ == "__main__":
    print(f"""
╔════════════════════════════════════════════════════════════╗
║    🎣 Honeypot Scam Detection API                         ║
╚════════════════════════════════════════════════════════════╝

Server: http://localhost:8000

🔐 AUTHENTICATION:
   Header: x-api-key
   Value: {API_KEY}

ENDPOINTS:
  POST /api/chat    - Process scam message (requires API key)
  GET  /health      - Health check (no auth)
  GET  /metrics     - Get metrics (requires API key)
  GET  /docs        - Swagger UI (no auth)

Documentation: http://localhost:8000/docs
""")
    
    try:
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            log_level="info"
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")

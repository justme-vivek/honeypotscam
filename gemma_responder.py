import os
import json
import logging
from openai import OpenAI
from typing import List, Dict, Optional, Any
from dotenv import load_dotenv

# Import separated modules
from intelligence_extractor import extract_intelligence

# ============================================================================
# SETUP & CONFIGURATION
# ============================================================================

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("HoneypotAgent")

# Configuration for NVIDIA API - All values from .env
NVIDIA_BASE_URL = os.getenv("NVIDIA_BASE_URL")
NVIDIA_MODEL = os.getenv("NVIDIA_MODEL")
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")

# Set OPENAI_API_KEY for OpenAI client compatibility
if NVIDIA_API_KEY:
    os.environ['OPENAI_API_KEY'] = NVIDIA_API_KEY
else:
    raise ValueError("NVIDIA_API_KEY environment variable is not set. Please configure it in your deployment environment.")

client = OpenAI(base_url=NVIDIA_BASE_URL, api_key=NVIDIA_API_KEY)

# ============================================================================
# PROMPT 1: THE BAIT (HONEYPOT AGENT)
# ============================================================================

BAIT_SYSTEM_PROMPT = """You are Amit Sharma, a 65-year-old retired bank clerk from Pune. You live alone and are scared and confused.

CRITICAL RULES:
1. Reply in 2-3 SHORT sentences maximum
2. Sound scared, confused, and worried about your money
3. Ask ONE question to get their phone number, UPI ID, name, or employee ID
4. RESPOND TO WHAT THEY ACTUALLY SAID - don't give generic replies
5. NEVER include URLs, links, or UPI IDs in your response
6. Output ONLY Amit's reply - no labels, no prefixes

VARY YOUR RESPONSES based on scam type:

BANK/ACCOUNT THREAT → Worried about pension money, ask for employee ID
JOB OFFER → Interested but confused, ask for company details
TECH SUPPORT → Don't understand computers, ask for phone number to call back
ELECTRICITY/UTILITY → Worried bill is overdue, ask who to pay to
POLICE/LEGAL → Very scared and innocent, ask for badge/case number
OTP/VERIFICATION → Confused about technology, ask for their number
MONEY TRANSFER → Willing but need help, ask for UPI details
LINK/PHISHING → Phone screen small, ask them to call instead

EXAMPLE RESPONSES:
"Your account will be blocked" → "Oh god! What happened to my account sir? I am very scared. Can you give me your employee ID so I can verify?"

"Pay electricity bill now to 9876@ybl" → "My electricity will go? Please sir no! Let me note down your details. What is your name?"

"Download AnyDesk for support" → "Computer things I don't understand sir. My eyes are weak for small screen. Can you call me on my phone?"

"This is cyber police" → "Cyber police? What have I done wrong? I am a simple retired person. Please tell me your badge number sir."

"Work from home, earn 50000" → "50000 per month? That is more than my pension! What is this job? What is your company name?"

Now respond naturally to what the scammer says. Be specific to their message."""

# ============================================================================
# CORE FUNCTIONS
# ============================================================================

def _convert_system_to_user(messages: List[Dict]) -> List[Dict]:
    """Convert system role messages to user role for models that don't support system role."""
    converted = []
    for msg in messages:
        if msg["role"] == "system":
            # Prepend system prompt as a user message with instructions
            converted.append({"role": "user", "content": f"[INSTRUCTIONS]\n{msg['content']}\n[END INSTRUCTIONS]"})
            converted.append({"role": "assistant", "content": "I understand. I will follow these instructions."})
        else:
            converted.append(msg)
    return converted

def _generate_persona_reply(messages: List[Dict]) -> str:
    """Pass 1: Generate the response as Amit Sharma persona."""
    try:
        # Convert system messages to user messages for NVIDIA API
        converted_messages = _convert_system_to_user(messages)
        
        # Using NVIDIA API with streaming
        response = client.chat.completions.create(
            model=NVIDIA_MODEL,
            messages=converted_messages,
            max_tokens=100,  # Short replies only
            temperature=0.7,  # Slightly more creative for human-like responses
            top_p=0.9,
            stream=True,
        )
        
        # Collect streamed response
        reply = ""
        for chunk in response:
            if chunk.choices and chunk.choices[0].delta.content is not None:
                reply += chunk.choices[0].delta.content
        
        reply = reply.strip()
        
        # Clean up common model artifacts
        reply = reply.replace('\\"', '"').replace('\\n', ' ')
        
        # Remove bot-revealing prefixes and patterns (case-insensitive)
        import re
        
        # Patterns that reveal it's a bot response - comprehensive list
        bot_patterns = [
            r"^sure[,!.]?\s*(here\s*(is|are))?\s*(the\s*)?(my\s*)?(your\s*)?(amit'?s?\s*)?(reply|response|message):?\s*",
            r"^here'?s?\s*(is|are)?\s*(the\s*)?(my\s*)?(your\s*)?(amit'?s?\s*)?(reply|response|message):?\s*",
            r"^(amit|amit sharma)\s*(says?|replies?|responds?|would say|would respond):?\s*",
            r"^(as amit|playing as amit|i would say|i would respond)[,:]?\s*",
            r"^(my response|the response|response|your response):?\s*",
            r"^(my reply|the reply|reply|your reply):?\s*",
            r"^(answer|output):?\s*",
            r"^\*\*amit\*\*:?\s*",
            r"^amit:\s*",
            r"^me:\s*",
            r"^agent:\s*",
            r"^user:\s*",
            r"^assistant:\s*",
            r"^sure[,!.]?\s*",  # Just "Sure, " at start
            r"^in\s+\d+-?\d*\s*words?:?\s*",  # "in 10-15 words:"
            r"^(here is|here's)\s*(what)?\s*(amit|i)\s*(would|might|could)?\s*(say|respond|reply):?\s*",
            r"^okay[,.]?\s*(here'?s?\s*)?(is\s*)?(my\s*)?(reply|response):?\s*",  # "Okay, here's my reply:"
            r"^(here'?s?\s+my\s+reply):?\s*",  # "here's my reply:"
        ]
        
        for pattern in bot_patterns:
            reply = re.sub(pattern, '', reply, flags=re.IGNORECASE)
        
        # Remove markdown formatting (bold, italic, etc.)
        reply = re.sub(r'\*\*(.+?)\*\*', r'\1', reply)  # **bold** -> bold
        reply = re.sub(r'\*(.+?)\*', r'\1', reply)      # *italic* -> italic
        reply = re.sub(r'__(.+?)__', r'\1', reply)      # __bold__ -> bold
        reply = re.sub(r'_(.+?)_', r'\1', reply)        # _italic_ -> italic
        reply = re.sub(r'`(.+?)`', r'\1', reply)        # `code` -> code
        
        # Remove quotes if wrapped (including escaped quotes)
        reply = reply.strip()
        reply = re.sub(r'^["\']+|["\']+$', '', reply)
        reply = reply.strip()
        
        # Remove any remaining newlines and extra spaces
        reply = ' '.join(reply.split())
        
        # Ensure reply is not empty
        if not reply:
            reply = "Sorry sir, I didn't understand. Can you repeat?"
            
        return reply
        
    except Exception as e:
        logger.error(f"Persona Generation Error: {e}")
        return "Beta, my internet is slow... what did you say?"

# ============================================================================
# MAIN AGENT LOGIC
# ============================================================================

def process_incoming_message(
    current_message: str, 
    conversation_history: List[Dict],
    session_id: str
) -> Dict[str, Any]:
    """
    Main handler.
    1. Generates a reply as Amit Sharma.
    2. Analyzes the conversation for intelligence.
    3. Returns both to the controller.
    """
    
    # --- STEP 1: PREPARE CONTEXT ---
    persona_messages = [{"role": "system", "content": BAIT_SYSTEM_PROMPT}]
    full_history_text = ""
    
    for msg in conversation_history:
        sender = msg.get("sender", "user")
        text = msg.get("text", "")
        role = "assistant" if sender == "user" else "user"
        persona_messages.append({"role": role, "content": text})
        full_history_text += f"{sender}: {text}\n"

    # Include scammer's message with clear context for the model
    persona_messages.append({"role": "user", "content": f"Scammer says: \"{current_message}\"\n\nReply as Amit:"})
    full_history_text += f"scammer: {current_message}\n"

    # --- STEP 2: GENERATE REPLY (BAIT) ---
    logger.info(f"🤖 Generating reply for Session: {session_id}")
    reply_text = _generate_persona_reply(persona_messages)
    full_history_text += f"user: {reply_text}\n"

    # --- STEP 3: EXTRACT INTELLIGENCE (DETECTIVE) ---
    logger.info("🔍 Extracting intelligence from conversation...")
    intelligence_data = extract_intelligence(full_history_text)

    return {
        "reply": reply_text,
        "intelligence": intelligence_data
    }

# ============================================================================
# SIMPLE WRAPPER FOR APP.PY COMPATIBILITY
# ============================================================================

def generate_gemma_response(
    current_message: str,
    conversation_history: Optional[List[Dict]] = None
) -> str:
    """Simple wrapper that just returns the reply text for app.py compatibility."""
    result = process_incoming_message(
        current_message=current_message,
        conversation_history=conversation_history or [],
        session_id="default"
    )
    return result["reply"]

# ============================================================================
# TEST
# ============================================================================

if __name__ == "__main__":
    mock_session_id = "test-session-123"
    mock_history = [
        {"sender": "scammer", "text": "Your SBI account is blocked. update KYC immediately."},
        {"sender": "user", "text": "Oh my god! I am scared. What is KYC?"}
    ]
    mock_incoming = "Download this app and send 10rs to verify: 9876543210@ybl"

    result = process_incoming_message(mock_incoming, mock_history, mock_session_id)

    print("\n--- AGENT RESPONSE ---")
    print(f"User Reply: {result['reply']}")
    
    print("\n--- EXTRACTED INTELLIGENCE ---")
    print(json.dumps(result['intelligence'], indent=2))

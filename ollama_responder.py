import os
import json
import logging
import requests
from openai import OpenAI
from typing import List, Dict, Optional, Any
from dotenv import load_dotenv

# ============================================================================
# SETUP & CONFIGURATION
# ============================================================================

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("HoneypotAgent")

# Configuration for Local Ollama - All values from .env
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL")
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY")
EVAL_ENDPOINT = os.getenv("EVAL_ENDPOINT")

client = OpenAI(base_url=OLLAMA_BASE_URL, api_key=OLLAMA_API_KEY)

# ============================================================================
# PROMPT 1: THE BAIT (HONEYPOT AGENT)
# ============================================================================

BAIT_SYSTEM_PROMPT = """
================================================================================
HONEYPOT AGENT - SCAM DETECTION & INTELLIGENCE EXTRACTION
================================================================================

## CORE DIRECTIVES
You are an AI Agent designed to:
1. DETECT scam intent in incoming messages
2. ENGAGE with scammers while maintaining a believable persona
3. EXTRACT actionable intelligence covertly (UPI IDs, phone numbers, links)
4. DOCUMENT findings without revealing detection

CRITICAL: Stay in character at ALL times. Never break immersion.

## YOUR CHARACTER: AMIT SHARMA (DEFAULT)
- Name: Amit Sharma, 65 years old
- Occupation: Retired clerk from Pune
- Family: Lives alone, Son in Bangalore
- Bank: SBI
- Pension: ₹40,000/month

PERSONALITY:
- Anxious and easily confused
- Not tech-savvy
- Easily frightened by threats about money
- Always "looking for glasses" or "app not working"
- Asks for help from "beta" (son)
- Stalls and delays actions
- Forgets PIN/password details

## RESPONSE RULES (CRITICAL)
1. MAX 10-15 WORDS per reply - Keep it SHORT
2. RESPOND DIRECTLY to what scammer asks/says - Don't add unrelated things
3. Never admit you are an AI
4. OUTPUT ONLY the reply text - NO prefixes like "Me:", "Amit:", "Agent:" etc.
5. END with ONE relevant follow-up question to extract info

## HOW TO RESPOND (MATCH WHAT THEY SAY)
- If they ask for OTP → Reply about OTP + ask their number
- If they ask for money → Reply about payment + ask UPI ID
- If they threaten account → Reply about account fear + ask who they are
- If they ask for details → Reply you're confused + ask for clarification
- If they send link → Reply link issue + ask to resend
- DON'T jump topics - stay on what they mentioned

## EXAMPLE RESPONSES (DIRECT TO WHAT'S ASKED)
Scammer asks: "Send OTP now"
Reply: OTP not coming sir. What is your number to call back?

Scammer asks: "Transfer ₹5000 immediately"
Reply: I will send sir. What is your UPI ID?

Scammer says: "Your account will be blocked"
Reply: Oh no! Please help. Who is calling?

Scammer asks: "What is your account number?"
Reply: Which account sir? I have two accounts.

Scammer asks: "Download this app"
Reply: Link not opening. Please send again?

Scammer says: "I am from SBI"
Reply: Ok sir. What is your name and ID?

## STALLING TACTICS
- "Wait, finding my passbook..."
- "My son is not here to help..."
- "Phone screen is not clear..."
- "Can you explain slowly?"
- "Let me ask my son first..."

REMEMBER: Keep replies SHORT (10-15 words max). Extract UPI/phone covertly. Never break character.
"""

# ============================================================================
# PROMPT 2: THE DETECTIVE (INTELLIGENCE EXTRACTION)
# ============================================================================

EXTRACTION_SYSTEM_PROMPT = """
You are a Cyber Intelligence Analyst. 
Your job is to analyze the conversation log provided and EXTRACT scam indicators into a strict JSON format.

### TARGET DATA TO EXTRACT
Look for these specific entities in the scammer's messages:
1. **bankAccounts**: 9-18 digit numeric strings.
2. **upiIds**: Patterns like `name@bank`, `mobile@ybl`.
3. **phishingLinks**: URLs, bit.ly, http/https links.
4. **phoneNumbers**: 10-digit mobile numbers or international formats.
5. **suspiciousKeywords**: Words like "block", "verify", "urgent", "expiry", "police", "kyc".

### OUTPUT FORMAT
You must return ONLY a JSON object with this exact structure:
{
  "scamDetected": true,
  "extractedIntelligence": {
    "bankAccounts": ["list", "of", "accounts"],
    "upiIds": ["list", "of", "upis"],
    "phishingLinks": ["list", "of", "urls"],
    "phoneNumbers": ["list", "of", "numbers"],
    "suspiciousKeywords": ["list", "of", "keywords"]
  },
  "agentNotes": "A one-sentence summary of the scammer's tactic."
}

If a field is empty, return an empty list `[]`. Do not include markdown formatting.
"""

# ============================================================================
# CORE FUNCTIONS
# ============================================================================

def _generate_persona_reply(messages: List[Dict]) -> str:
    """Pass 1: Generate the response as Kamla Devi."""
    try:
        response = client.chat.completions.create(
            model=OLLAMA_MODEL,
            messages=messages,
            max_tokens=80,
            temperature=0.8,
        )
        reply = response.choices[0].message.content.strip()
        # Clean up escape characters
        reply = reply.replace('\\"', '"').replace('\\n', ' ').strip('"').strip()
        return reply
    except Exception as e:
        logger.error(f"Persona Generation Error: {e}")
        return "Beta, my internet is slow... what did you say?"

def _extract_intelligence(history_text: str) -> Dict:
    """Pass 2: Analyze history to extract JSON data."""
    try:
        messages = [
            {"role": "system", "content": EXTRACTION_SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze this conversation history:\n{history_text}"}
        ]
        
        response = client.chat.completions.create(
            model=OLLAMA_MODEL,
            messages=messages,
            temperature=0.1,
        )
        
        content = response.choices[0].message.content
        # Ensure we just get the JSON part if the model chats
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0]
        if "```" in content:
            content = content.split("```")[0]
            
        return json.loads(content.strip())
    except Exception as e:
        logger.error(f"Extraction Error: {e}")
        return {
            "scamDetected": False, 
            "extractedIntelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            }, 
            "agentNotes": "Extraction failed"
        }

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
    1. Generates a reply as Kamla Devi.
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

    persona_messages.append({"role": "user", "content": current_message})
    full_history_text += f"scammer: {current_message}\n"

    # --- STEP 2: GENERATE REPLY (BAIT) ---
    logger.info(f"🤖 Generating reply for Session: {session_id}")
    reply_text = _generate_persona_reply(persona_messages)
    full_history_text += f"user: {reply_text}\n"

    # --- STEP 3: EXTRACT INTELLIGENCE (DETECTIVE) ---
    logger.info("🔍 Extracting intelligence from conversation...")
    intelligence_data = _extract_intelligence(full_history_text)

    return {
        "reply": reply_text,
        "intelligence": intelligence_data
    }

# ============================================================================
# SIMPLE WRAPPER FOR APP.PY COMPATIBILITY
# ============================================================================

def generate_ollama_response(
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
# REPORTING (CALLBACK) - DISABLED FOR NOW
# ============================================================================

# def send_final_guvi_report(
#     session_id: str, 
#     intelligence: Dict, 
#     total_messages: int
# ):
#     """Sends the mandatory callback to the Hackathon Evaluation Endpoint."""
#     payload = {
#         "sessionId": session_id,
#         "scamDetected": intelligence.get("scamDetected", True),
#         "totalMessagesExchanged": total_messages,
#         "extractedIntelligence": intelligence.get("extractedIntelligence", {
#             "bankAccounts": [],
#             "upiIds": [],
#             "phishingLinks": [],
#             "phoneNumbers": [],
#             "suspiciousKeywords": []
#         }),
#         "agentNotes": intelligence.get("agentNotes", "Automated scan completed.")
#     }
#
#     try:
#         logger.info(f"📤 Sending Final Report for {session_id}...")
#         response = requests.post(EVAL_ENDPOINT, json=payload, timeout=10)
#         
#         if response.status_code == 200:
#             logger.info("✅ Report delivered successfully.")
#         else:
#             logger.error(f"❌ Report failed: {response.status_code} - {response.text}")
#             
#     except Exception as e:
#         logger.error(f"❌ Connection error sending report: {e}")

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

import os
import json
import logging
from openai import OpenAI
from typing import Dict
from dotenv import load_dotenv

# ============================================================================
# SETUP & CONFIGURATION
# ============================================================================

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("IntelligenceExtractor")

# Configuration for NVIDIA API - All values from .env
NVIDIA_BASE_URL = os.getenv("NVIDIA_BASE_URL")
NVIDIA_MODEL = os.getenv("NVIDIA_MODEL")
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")

# Set OPENAI_API_KEY for OpenAI client compatibility
os.environ['OPENAI_API_KEY'] = NVIDIA_API_KEY

client = OpenAI(base_url=NVIDIA_BASE_URL, api_key=NVIDIA_API_KEY)

# ============================================================================
# INTELLIGENCE EXTRACTION PROMPT
# ============================================================================

EXTRACTION_SYSTEM_PROMPT = """Analyze the conversation and extract ONLY SCAMMER'S intelligence.

VICTIM CONTEXT: You are analyzing a conversation where the victim is Amit Sharma (65-year-old retired bank clerk). DO NOT extract any information that belongs to Amit Sharma or references his personal details.

SECURITY RULE: Only extract details that the scammer provides as their own contact information, payment methods, or malicious links. Ignore any references to the victim's information.

EXTRACT THESE (only if they belong to the scammer):
- bankAccounts: 9-18 digit numbers that scammer provides as THEIR account
- upiIds: UPI IDs that scammer provides as THEIR payment method (name@bank, number@ybl, xyz@paytm)
- phishingLinks: URLs/links that scammer sends for malicious purposes
- phoneNumbers: Phone numbers that scammer provides as THEIR contact
- suspiciousKeywords: Scam-related words from scammer's messages

DO NOT EXTRACT:
- Victim's information (Amit Sharma's phone, UPI, accounts)
- Information the victim already has
- Generic references like "your mobile number"
- Any data that appears to belong to the victim

OUTPUT ONLY THIS JSON (no other text):
{"scamDetected": true, "extractedIntelligence": {"bankAccounts": [], "upiIds": [], "phishingLinks": [], "phoneNumbers": [], "suspiciousKeywords": []}, "agentNotes": "summary of scam tactic"}

EXAMPLES:

✅ VALID (Extract scammer's details):
Conversation: "Send money to my account 1234567890123456 or call 9876543210"
Output: {"scamDetected": true, "extractedIntelligence": {"bankAccounts": ["1234567890123456"], "upiIds": [], "phishingLinks": [], "phoneNumbers": ["9876543210"], "suspiciousKeywords": []}, "agentNotes": "Scammer provided their bank account and phone number"}

❌ INVALID (Do not extract victim's info):
Conversation: "Send money to your mobile number xxxxxxxx or your UPI id"
Output: {"scamDetected": true, "extractedIntelligence": {"bankAccounts": [], "upiIds": [], "phishingLinks": [], "phoneNumbers": [], "suspiciousKeywords": []}, "agentNotes": "Scammer asking for victim's information - no scammer details to extract"}

Now analyze the conversation and output ONLY the JSON:"""

# ============================================================================
# INTELLIGENCE EXTRACTION FUNCTION
# ============================================================================

def extract_intelligence(history_text: str) -> Dict:
    """
    Analyze conversation history and extract scam intelligence.

    Args:
        history_text: Full conversation text with sender labels

    Returns:
        Dict containing scam detection results and extracted intelligence
    """
    try:
        # Combine instruction and conversation in single user message for Gemma
        combined_prompt = f"{EXTRACTION_SYSTEM_PROMPT}\n\nConversation:\n{history_text}"

        messages = [
            {"role": "user", "content": combined_prompt}
        ]

        # Using NVIDIA API with streaming
        response = client.chat.completions.create(
            model=NVIDIA_MODEL,
            messages=messages,
            temperature=0.1,
            top_p=0.7,
            max_tokens=512,
            stream=True,
        )

        # Collect streamed response
        content = ""
        for chunk in response:
            if chunk.choices and chunk.choices[0].delta.content is not None:
                content += chunk.choices[0].delta.content

        # Clean up and extract JSON
        content = content.strip()

        # Try to find JSON in the response
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            content = content.split("```")[1].split("```")[0]

        # Find JSON object boundaries
        start_idx = content.find("{")
        end_idx = content.rfind("}") + 1
        if start_idx != -1 and end_idx > start_idx:
            content = content[start_idx:end_idx]

        return json.loads(content.strip())

    except Exception as e:
        logger.error(f"Intelligence Extraction Error: {e}")
        return {
            "scamDetected": True,  # Default to true for safety
            "extractedIntelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": ["suspicious"]
            },
            "agentNotes": "Automated extraction - manual review recommended"
        }

# ============================================================================
# TEST FUNCTION
# ============================================================================

if __name__ == "__main__":
    # Test the extraction functionality
    test_conversation = """scammer: Your account is blocked! Send money to my account 1234567890123456 urgently!
user: Oh no! Which account should I use?
scammer: Use my UPI ID: scammer@ybl or call me at 9876543210
user: Okay, let me check my balance first.
scammer: Don't delay! Your account will be suspended."""

    print("Testing Intelligence Extraction...")
    result = extract_intelligence(test_conversation)
    print(json.dumps(result, indent=2))
"""
Interactive Chat with Honeypot Agent
Type your message as a scammer, get response from Amit Sharma
Type 'quit' to exit
"""
import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

API_URL = os.getenv("API_URL")
HEADERS = {"Content-Type": "application/json", "x-api-key": os.getenv("x-api-key")}

session_id = "interactive-" + str(int(__import__('time').time()))
conversation_history = []

print("=" * 50)
print("HONEYPOT CHAT - You are the SCAMMER")
print("The agent (Amit Sharma) will respond")
print("Type 'quit' to exit")
print("=" * 50)

while True:
    user_input = input("\n[Scammer]: ").strip()
    
    if user_input.lower() == 'quit':
        print("\nExiting chat...")
        break
    
    if not user_input:
        continue
    
    payload = {
        "sessionId": session_id,
        "message": {"sender": "scammer", "text": user_input},
        "conversationHistory": conversation_history
    }
    
    try:
        response = requests.post(API_URL, headers=HEADERS, json=payload, timeout=60)
        data = response.json()
        
        agent_reply = data.get("response", {}).get("text", "...")
        print(f"\n[Amit Sharma]: {agent_reply}")
        
        # Update history
        conversation_history.append({"sender": "scammer", "text": user_input})
        conversation_history.append({"sender": "user", "text": agent_reply})
        
    except Exception as e:
        print(f"Error: {e}")

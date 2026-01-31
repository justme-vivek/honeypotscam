import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL")
API_URL = os.getenv("API_URL")
API_KEY = os.getenv("x-api-key")

# Test Ollama directly
url = f"{OLLAMA_BASE_URL}/chat/completions"
payload = {
    "model": OLLAMA_MODEL,
    "messages": [
        {"role": "user", "content": "Hello, say 'Ollama is working!'"}
    ]
}

try:
    response = requests.post(url, json=payload, timeout=10)
    print(f"Ollama Status: {response.status_code}")
    data = response.json()
    print(f"Response: {data['choices'][0]['message']['content']}")
except Exception as e:
    print(f"Ollama Error: {e}")

# Test API
print("\n--- Testing API ---")
headers = {"Content-Type": "application/json", "x-api-key": API_KEY}
api_payload = {
    "sessionId": "verify-ollama-1",
    "message": {"sender": "scammer", "text": "Send me your OTP right now!"},
    "conversationHistory": []
}
try:
    response = requests.post(API_URL, headers=headers, json=api_payload, timeout=30)
    data = response.json()
    print(f"API Status: {response.status_code}")
    print(f"Agent Response: {data.get('response', {}).get('text', 'No text')}")
except Exception as e:
    print(f"API Error: {e}")

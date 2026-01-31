import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

url = os.getenv("API_URL")
headers = {
    "Content-Type": "application/json",
    "x-api-key": os.getenv("x-api-key")
}
payload = {
    "sessionId": "test-ollama-1",
    "message": {
        "sender": "scammer",
        "text": "Your bank account will be blocked. Send OTP now."
    },
    "conversationHistory": []
}

try:
    response = requests.post(url, headers=headers, json=payload, timeout=30)
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"Error: {e}")

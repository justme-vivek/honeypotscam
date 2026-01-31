import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

API_URL = os.getenv("API_URL", "http://localhost:8000/api/chat")
API_KEY = os.getenv("x-api-key", "dev-secret-key-12345")

payload = {
    "message": {
        "text": "Your bank account is blocked. Send OTP immediately.",
        "sender": "scammer"
    },
    "sessionId": "manual_test_001"
}

headers = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
}

print(f"Testing API at: {API_URL}")
try:
    response = requests.post(API_URL, json=payload, headers=headers)
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print("\nResponse Keys:", list(data.keys()))
        print("\nFull Response:")
        print(json.dumps(data, indent=2))
        
        if "message" in data:
            print("\n✅ 'message' field verification:")
            print(f"Type: {type(data['message'])}")
            print(f"Value: {data['message']}")
        else:
            print("\n❌ 'message' field MISSING")
            
    else:
        print("Error Response:", response.text)

except Exception as e:
    print(f"Request failed: {e}")

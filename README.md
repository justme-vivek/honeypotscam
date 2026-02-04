<div align="center">

# 🎣 Honeypot Scam Detection API

### _AI-Powered Scam Detection & Intelligence Extraction System_

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![NVIDIA](https://img.shields.io/badge/NVIDIA-Gemma_7B-76B900?style=for-the-badge&logo=nvidia&logoColor=white)](https://nvidia.com)
[![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org)

[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)
[![GUVI](https://img.shields.io/badge/GUVI-Hackathon-FF6B6B?style=flat-square)](https://guvi.in)

<p align="center">
  <img src="https://img.shields.io/badge/🔒_Security-First-critical?style=for-the-badge" alt="Security First"/>
  <img src="https://img.shields.io/badge/🤖_AI-Powered-blueviolet?style=for-the-badge" alt="AI Powered"/>
  <img src="https://img.shields.io/badge/⚡_Real--Time-Detection-orange?style=for-the-badge" alt="Real-Time"/>
</p>

---

**A sophisticated AI-powered honeypot system that engages scammers in realistic conversations, extracts critical intelligence (bank accounts, UPI IDs, phone numbers), and reports to fraud prevention systems.**

[🚀 Quick Start](#-quick-start) •
[📖 Documentation](#-api-documentation) •
[🏗️ Architecture](#️-architecture) •
[🌐 Deployment](#-deployment-options)

</div>

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🎭 Intelligent Persona

- **Amit Sharma** - A convincing 62-year-old retired bank manager
- Authentic Hindi-English conversation style
- Context-aware multi-turn dialogues
- Realistic response timing

</td>
<td width="50%">

### 🔍 Scam Intelligence

- Automatic extraction of scammer details
- Bank account & UPI ID detection
- Phishing link identification
- Phone number capture

</td>
</tr>
<tr>
<td width="50%">

### 🛡️ Security First

- API key authentication
- No victim data extraction
- Secure database architecture
- CORS protection enabled

</td>
<td width="50%">

### 📊 Real-Time Analytics

- Live session monitoring
- Scam confirmation system
- GUVI integration for reporting
- Comprehensive metrics

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Prerequisites

| Requirement                                                                              | Version | Purpose         |
| ---------------------------------------------------------------------------------------- | ------- | --------------- |
| ![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)    | 3.11+   | Runtime         |
| ![pip](https://img.shields.io/badge/pip-Latest-orange?logo=pypi&logoColor=white)         | Latest  | Package Manager |
| ![NVIDIA](https://img.shields.io/badge/NVIDIA_API-Key-green?logo=nvidia&logoColor=white) | -       | AI Engine       |

### ⚡ Installation

#### 1️⃣ Clone the Repository

```bash
git clone https://github.com/justme-vivek/honeypotscam.git
cd honeypotscam
```

#### 2️⃣ Create Virtual Environment

```powershell
# Windows
python -m venv venv
```

```bash
# Linux/macOS
python3 -m venv venv
```

#### 3️⃣ Install Dependencies

```powershell
# Windows
.\venv\Scripts\pip.exe install -r requirements.txt
```

```bash
# Linux/macOS
./venv/bin/pip install -r requirements.txt
```

#### 4️⃣ Configure Environment

Create a `.env` file in the project root:

```env
# Environment
ENVIRONMENT=development
LOG_LEVEL=INFO

# API Security
x-api-key=your-secure-api-key-here

# NVIDIA AI Configuration
NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1
NVIDIA_MODEL=google/gemma-7b
NVIDIA_API_KEY=your-nvidia-api-key-here

# GUVI Integration
EVAL_ENDPOINT=https://hackathon.guvi.in/api/updateHoneyPotFinalResult

# Server Configuration
web_hook_port=8000
```

#### 5️⃣ Run the Server

```powershell
# Windows (PowerShell) - Recommended ✅
$env:PYTHONUTF8=1; .\venv\Scripts\python.exe app.py
```

```bash
# Linux/macOS
./venv/bin/python app.py
```

<details>
<summary>📋 Expected Output</summary>

```
╔════════════════════════════════════════════════════════════╗
║    🎣 Honeypot Scam Detection API                         ║
╚════════════════════════════════════════════════════════════╝

Server: http://localhost:8000

🔐 AUTHENTICATION:
   Header: x-api-key
   Value: your-api-key

ENDPOINTS:
  POST /api/chat              - Process scam message
  POST /api/end-session       - Finalize a session manually
  POST /api/push-to-guvi      - Push pending scams to GUVI
  GET  /health                - Health check (no auth)
  GET  /docs                  - Swagger UI

⏰ SESSION TIMEOUT: 5 minutes (auto-finalize, no GUVI push)
📤 GUVI CALLBACK: On manual session disconnect

Documentation: http://localhost:8000/docs
```

</details>

---

## 📖 API Documentation

### 🔐 Authentication

All protected endpoints require the `x-api-key` header:

```http
x-api-key: your-secure-api-key-here
```

### 📡 Endpoints

<details open>
<summary><b>Core Endpoints</b></summary>

| Method | Endpoint    | Auth | Description                   |
| ------ | ----------- | ---- | ----------------------------- |
| `POST` | `/api/chat` | ✅   | Process incoming scam message |
| `GET`  | `/health`   | ❌   | Health check                  |
| `GET`  | `/ping`     | ❌   | Keep-alive ping               |
| `GET`  | `/docs`     | ❌   | Swagger UI documentation      |

</details>

<details>
<summary><b>Management Endpoints</b></summary>

| Method | Endpoint                   | Auth | Description                                                  |
| ------ | -------------------------- | ---- | ------------------------------------------------------------ |
| `POST` | `/api/end-session`         | ✅   | Manually finalize a session (pushes confirmed scams to GUVI) |
| `POST` | `/api/finalize-timeout`    | ✅   | Process timed-out sessions                                   |
| `POST` | `/api/push-to-guvi`        | ✅   | Push pending scams to GUVI                                   |
| `POST` | `/api/clear-all-data`      | ✅   | Clear all databases                                          |
| `GET`  | `/api/view-db/{type}`      | ✅   | View database contents                                       |
| `GET`  | `/api/session-status/{id}` | ✅   | Get session scam status                                      |
| `GET`  | `/metrics`                 | ✅   | Service metrics                                              |

</details>

### 💬 Chat API Example

**Request:**

```json
POST /api/chat
Headers: { "x-api-key": "your-api-key" }

{
  "sessionId": "session-123",
  "message": {
    "sender": "scammer",
    "text": "Dear customer, your SBI account has been blocked. Share OTP immediately."
  },
  "conversationHistory": []
}
```

**Response:**

```json
{
  "status": "success",
  "reply": "Arey beta, mera account blocked? Lekin main toh abhi ATM se paise nikala... kya problem hai?"
}
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         🎣 HONEYPOT SYSTEM                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────┐  │
│  │   FastAPI    │───▶│  Gemma Responder │───▶│   Intelligence   │  │
│  │   Server     │    │  (Amit Sharma)   │    │   Extractor      │  │
│  └──────────────┘    └──────────────────┘    └──────────────────┘  │
│         │                                              │            │
│         ▼                                              ▼            │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                      DATABASE LAYER                          │  │
│  │  ┌────────────────┐ ┌────────────────┐ ┌────────────────┐   │  │
│  │  │ current_session│ │ chat_sessions  │ │ scam_session   │   │  │
│  │  │    .db         │ │    .db         │ │    .db         │   │  │
│  │  │  (Active)      │ │  (Archive)     │ │  (GUVI Ready)  │   │  │
│  │  └────────────────┘ └────────────────┘ └────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                   │                                 │
│                                   ▼                                 │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    GUVI REPORTER                              │  │
│  │           📤 Push confirmed scams to evaluation               │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 📁 Project Structure

```
honeypotscam/
├── 📄 app.py                    # FastAPI main application
├── 📄 gemma_responder.py        # AI persona & response generation
├── 📄 intelligence_extractor.py # Scam intelligence extraction
├── 📄 guvi_reporter.py          # GUVI callback integration
├── 📄 db_manager.py             # Database operations
├── 📄 requirements.txt          # Python dependencies
├── 📄 .env                      # Environment configuration
├── 📄 keep_alive.py             # Keep-alive script for Render
├── 📄 view_db_panel.html        # Database monitoring UI
├── 📂 tests/                    # Test suites
│   ├── 📂 unit/
│   ├── 📂 integration/
│   └── 📂 e2e/
└── 📂 venv/                     # Virtual environment
```

---

## 🌐 Deployment Options

### 🥇 Railway (Recommended)

<img src="https://img.shields.io/badge/Railway-Recommended-blueviolet?style=for-the-badge&logo=railway&logoColor=white" alt="Railway"/>

**Why Railway?**

- ✅ No sleep after inactivity
- ✅ Perfect for real-time applications
- ✅ Background processes run 24/7
- ✅ Automatic deployments from GitHub

**Deploy:**

1. Connect GitHub repository
2. Add environment variables
3. Deploy 🚀

### 🥈 Render (With Keep-Alive)

<img src="https://img.shields.io/badge/Render-Free_Tier-46E3B7?style=for-the-badge&logo=render&logoColor=white" alt="Render"/>

**Issue:** Free tier sleeps after 15 minutes of inactivity

**Solution:** Use UptimeRobot or GitHub Actions to ping `/ping` endpoint every 10 minutes

#### Render Deployment Steps:

1. **Create Render Web Service**
   - Connect your GitHub repository
   - Runtime: `Python 3`
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `python app.py`

2. **Environment Variables** (add these in Render dashboard):

   ```
   ENVIRONMENT=production
   x-api-key=your-secure-api-key-here
   NVIDIA_API_KEY=your-nvidia-api-key-here
   NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1
   NVIDIA_MODEL=google/gemma-7b
   EVAL_ENDPOINT=https://hackathon.guvi.in/api/updateHoneyPotFinalResult
   ```

3. **Keep-Alive Setup** (choose one):

   **Option A: UptimeRobot (Recommended)**
   - Create free account at [uptimerobot.com](https://uptimerobot.com)
   - Add monitor: `https://honeypotscam.onrender.com/ping`
   - Set interval: 10 minutes

   **Option B: GitHub Actions**

   ```yaml
   name: Keep Render Alive
   on:
     schedule:
       - cron: "*/10 * * * *"
   jobs:
     ping:
       runs-on: ubuntu-latest
       steps:
         - run: curl -f https://honeypotscam.onrender.com/ping
   ```

**✅ Ready for Render:** The app now uses `PORT` environment variable automatically.

---

## 📊 GUVI Integration

The system reports confirmed scams to GUVI when sessions are manually disconnected via `/api/end-session`. Automatic timeout finalization (5 minutes) does not trigger GUVI reports.

Reported data format:

```json
{
  "sessionId": "abc123-session-id",
  "scamDetected": true,
  "totalMessagesExchanged": 18,
  "extractedIntelligence": {
    "bankAccounts": ["XXXX-XXXX-XXXX"],
    "upiIds": ["scammer@upi"],
    "phishingLinks": ["http://malicious-link.example"],
    "phoneNumbers": ["+91XXXXXXXXXX"],
    "suspiciousKeywords": ["urgent", "verify now", "account blocked"]
  },
  "agentNotes": "Scammer used urgency tactics and payment redirection"
}
```

---

## 🧪 Testing

```powershell
# Run all tests
$env:PYTHONUTF8=1; .\venv\Scripts\python.exe -m pytest tests/ -v

# Run specific test suites
.\venv\Scripts\python.exe -m pytest tests/unit/ -v
.\venv\Scripts\python.exe -m pytest tests/integration/ -v
.\venv\Scripts\python.exe -m pytest tests/e2e/ -v
```

---

## 🔧 Configuration

| Variable         | Description            | Default                 |
| ---------------- | ---------------------- | ----------------------- |
| `x-api-key`      | API authentication key | Required                |
| `NVIDIA_API_KEY` | NVIDIA API access key  | Required                |
| `NVIDIA_MODEL`   | AI model to use        | `google/gemma-7b`       |
| `EVAL_ENDPOINT`  | GUVI callback URL      | GUVI hackathon endpoint |
| `ENVIRONMENT`    | Runtime environment    | `development`           |
| `LOG_LEVEL`      | Logging verbosity      | `INFO`                  |

---

## 📈 Monitoring

### Database Panel

Access `view_db_panel.html` in your browser for real-time monitoring:

- 📍 Active sessions
- 📦 Archived conversations
- 🚨 Confirmed scam intelligence
- 📊 System statistics

### Metrics Endpoint

```bash
GET /metrics
```

Returns:

- Total messages processed
- Active sessions count
- Scams detected
- GUVI push statistics

---

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines first.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **GUVI** - For hosting the hackathon
- **NVIDIA** - For Gemma AI model access
- **FastAPI** - For the awesome web framework

---

<div align="center">

**Built with ❤️ for fraud detection and user safety**

[![Made with Python](https://img.shields.io/badge/Made%20with-Python-1f425f?style=for-the-badge&logo=python&logoColor=white)](https://python.org)

<sub>🎣 Catching scammers, one conversation at a time</sub>

</div>

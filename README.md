---
title: ShieldDB API
emoji: 🛡️
colorFrom: blue
colorTo: purple
sdk: docker
app_port: 8000
pinned: false
---

# ShieldDB 🛡️
### The Secured Google Gemini Database Workstation & MCP Gateway

**[▶ Watch Demo Video](https://drive.google.com/file/d/1QgQGtwEuir9pzHgEuJzfssrkNn6IIMuy/view?usp=sharing)**

---

**ShieldDB** is an enterprise-grade Model Context Protocol (MCP) gateway, security sidecar, and interactive workstation that enables **Google Gemini** to securely administer databases. Powered by **gemini-3.5-flash**, the workstation translates plain English instructions into complex database operations. To ensure enterprise compliance and prevent malicious exploits, all Gemini database interactions are intercepted and audited by **DuoGuard-0.5B**—a state-of-the-art multilingual safety classifier that blocks inbound prompt injections and automatically redacts outbound customer PII.

---

## 🌟 Key Features

1. **Autonomous Gemini Database Workstation 🤖**
   - Employs **Google Gemini (`gemini-3.5-flash`)** as the primary cognitive engine.
   - Translates complex natural language prompts (e.g., *"Give me a summary of active users in NY and update their status to active"*) into safe, structured database commands via Model Context Protocol (MCP) tool bindings.

2. **Inbound Guardrails (Safety Shielding) 🛡️**
   - Intercepts Gemini's incoming instructions to protect database collections against prompt injections, bypass attempts, and destructive command injections.
   - Detects risks across **12 distinct safety categories** (Jailbreak prompts, Non-violent crimes, Violent crimes, Suicide, etc.) in milliseconds.

3. **Outbound Guardrails (PII & Privacy Redaction) 🔒**
   - Automatically sanitizes retrieved query results *before* sending them to Gemini or rendering them in the chat workspace.
   - Intelligently redacts Emails, Credit Cards, Social Security Numbers, Phone Numbers, Passwords, and API Keys.
   - Enables full compliance with strict privacy standards like **GDPR, HIPAA, and PCI-DSS**.

4. **Smart Hybrid Database Engine ⚙️**
   - Automatically detects live MongoDB Atlas credentials in the environment.
   - Falls back to an **In-Memory Sandbox (MongoMock)** if offline, pre-seeding it with rich customer records so judges can run and evaluate the system instantly.

5. **Premium Security & Chat Dashboard 💎**
   - Includes the **Gemini Secure Brain** workspace—a clean, real-time interactive chat dashboard to instruct Gemini in plain English.
   - Features a **Live Security Console & Playground** to test benign vs. malicious prompts and visualize DuoGuard risk profiles and query redactors in real-time.

---

## 🛠️ Architecture

```
User Prompt ──> [Google Gemini (gemini-3.5-flash)]
                             │
                             ▼  (Secure MCP Tool Call)
                   [ShieldDB MCP Gateway]
                             │
        ┌────────────────────┴────────────────────┐
        ▼                                         ▼
[Inbound Screening]                      [Database Adapter]
DuoGuard Model Audit                    MongoDB or MongoMock
(Blocks Jailbreaks / Injections)          (Executes Safe Command)
                                                  │
                                                  ▼
                                        [Outbound Redaction]
                                       Scrub Emails/CC/PII
                                                  │
                             ┌────────────────────┘
                             ▼
                (Sanitized Query Results)
                             │
                             ▼
               [Google Gemini AI Brain]
                             │
                             ▼
                    Safe Natural Response
```

---

## 🚀 Installation & Local Startup

Ensure you have **Python 3.10+** and the **`uv`** package manager installed.

### 0. Environment Setup
To enable the interactive Gemini chat agent workspace, set your Google Gemini API key as an environment variable (or create a `.env` file in the root directory):
```bash
export GEMINI_API_KEY="your_gemini_api_key_here"
```

### 1. Pre-download Safety Models
To ensure instant startup, pre-cache the DuoGuard weights and tokenizers locally:
```bash
uv run python -m duogaurd_mcp.main download
```

### 2. Start the Security Dashboard & API Backend
Launch the FastAPI REST API serving telemetry and playgrounds:
```bash
uv run python -m duogaurd_mcp.main dashboard
```
*The API will be available at http://localhost:8000.*

### 3. Run the MCP Server (stdio)
To connect ShieldDB to Claude Desktop or Cursor IDE, run:
```bash
uv run python -m duogaurd_mcp.main run
```

---

## 📂 Project Structure

```
duogaurd_mcp/
├── pyproject.toml              # UV dependency metadata
├── README.md                   # System documentation
├── duogaurd_mcp/
│   ├── __init__.py
│   ├── moderator.py            # Safety classification & PII regex redactor
│   ├── database.py             # MongoDB connection & sandbox seed generator
│   ├── server.py               # Secure FastMCP tools
│   ├── api.py                  # FastAPI REST endpoints
│   ├── main.py                 # CLI controller (run, dashboard, download)
│   └── test.py                 # Diagnostic test suite
└── dashboard/                  # React dashboard
```

---

## 🛡️ License
Open-Source under the MIT License. Built for the Google Cloud Rapid Agent Hackathon.

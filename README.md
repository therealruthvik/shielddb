# ShieldDB 🛡️
### The Guarded Autonomous Database Administrator

**ShieldDB** is an enterprise-grade Model Context Protocol (MCP) gateway and security dashboard that secures AI agent interactions with databases. Powered by **DuoGuard-0.5B**, a state-of-the-art multilingual safety classifier, ShieldDB intercepts inbound natural language queries to prevent jailbreaks/attacks and scrubs outbound retrieved documents to automatically redact customer PII.

---

## 🌟 Key Features

1. **Inbound Guardrails (Safety Shielding)**
   - Protects database collections against prompt injections, bypass rules, and malicious command injections disguised as natural language.
   - Detects risks across **12 distinct safety categories** (Violent crimes, Child exploitation, Suicide, Hate speech, Jailbreaks, etc.).

2. **Outbound Guardrails (PII & Privacy Scrubbing)**
   - Automatically sanitizes retrieved query results *before* sending them to the AI agent or displaying them.
   - Intelligently redacts Emails, Credit Cards, Social Security Numbers, Phone Numbers, Passwords, and API Keys.
   - Helps meet corporate compliance frameworks like **GDPR, HIPAA, and PCI-DSS**.

3. **Smart Hybrid Database Engine**
   - Automatically detects live MongoDB Atlas credentials in a `.env` file.
   - Falls back to an **In-Memory Sandbox (MongoMock)** if offline, pre-seeding it with rich customer records so judges can run and evaluate the system instantly.

4. **Premium Security Dashboard**
   - A modern React dashboard with neon glows and glassmorphic panels.
   - Includes a **Live Security Console & Playground** to test benign vs. malicious prompts and visualize DuoGuard risk profiles and query redactors in real-time.

---

## 🛠️ Architecture

```
User Prompt ──> [AI Agent]
                  │
                  ▼  (secure_query tool call)
            [ShieldDB MCP Gateway]
                  │
                  ├── Inbound Screening (DuoGuard Model) ──> [Jailbreak? Blocked!]
                  │
                  ├── Database Adapter ──> [MongoDB / MongoMock]
                  │
                  └── Outbound Redaction ──> [Scrub Emails / CC / PII]
                  │
                  ▼  (Sanitized documents)
             [AI Agent] ──> Response to User
```

---

## 🚀 Installation & Local Startup

Ensure you have **Python 3.10+** and the **`uv`** package manager installed.

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

# 🛡️ NeuroShield

> **A Distributed Enterprise Threat Detection & Response (EDR / SIEM) Platform powered by Behavioral Transformer AI.**

NeuroShield is a world-class, production-grade security architecture designed to defend enterprise fleets against ransomware and zero-day exploits. By combining lightweight, distributed endpoint monitoring agents with a centralized deep learning analytics engine and a real-time Security Operations Center (SOC) dashboard, NeuroShield provides end-to-end detection, analysis, and autonomous response.

---

## 👑 Leadership & Credits
* **Lead Security Architect & Developer**: **Eng. Abdulrahman Jaber Al-Faifi**
* **Machine Learning & Core Architecture**: NeuroShield Security Research Group

---

## 🏛️ System Architecture

NeuroShield is structured into three highly optimized modules:
1. **Endpoint EDR Agent** (`agent.py`): A lightweight background worker that intercepts process system calls, tokenizes sequences on-the-fly, and transmits telemetry.
2. **Central Flask AI Backend** (`app.py`): The brain of the platform. Evaluates behavioral sequences using a custom Keras Transformer model, logs events to SQLite, triggers WhatsApp alerts, and enforces quarantine directives.
3. **Next.js SOC Dashboard** (`frontend`): A premium glassmorphism interface displaying a live telemetry log stream, real-time metrics, interactive threat simulation, and automated PDF report downloads.

```text
+---------------------------------------------------------------------------------+
|                                 NEUROSHIELD                                     |
|              Distributed Threat Detection & Response Platform                   |
+---------------------------------------------------------------------------------+

                      +---------------------------------------+
                      |       Distributed Python Agents       |
                      |   (agent.py / Compiled Windows EXE)   |
                      +---------------------------------------+
                                          |
                                          | [1] Telemetry Payload:
                                          |     - API Call Sequences (100 depth)
                                          |     - Metadata: PID, Process Name, Hostname
                                          v
                      +---------------------------------------+
                      |       Central Flask AI Backend        |
                      |              (app.py)                 |
                      +---------------------------------------+
                         /                |                 \
                        /                 |                  \
    [2] Feed Sequence  /    [3] Log Alert |      [4] Dispatch \
                      v                   v                    v
         +-----------------+     +-----------------+     +-----------------------+
         |   Transformer   |     | SQLite Database |     | WhatsApp CallMeBot    |
         |  Neural Network |     | (neuroshield_   |     |      API Gateway      |
         | (neuroshield_   |     |     soc.db)     |     | (Instant Alerting:    |
         |  transformer.h5)|     +-----------------+     |  🚨, 🖥️, ☣️, 🔒)        |
         +-----------------+              ^              +-----------------------+
                                          |
                                          | [5] Read Alerts / Clear Logs / Export PDF
                                          |
                                          v
                      +---------------------------------------+
                      |          Next.js SOC Dashboard        |
                      |             (frontend/app)            |
                      +---------------------------------------+
```

---

## 🚀 Advanced Features

### 🧠 1. Custom Transformer Behavior Analytics
Instead of relying on fragile file signatures, NeuroShield evaluates the **behavioral intent** of running processes. 
- Core classification is handled by a deep **Behavioral Transformer Encoder** model built with multi-head self-attention and positional encoding.
- Analyzes sequences of **100 consecutive API system calls** to detect ransomware encryption loops.
- Delivers exceptional performance metrics: **98.48% Accuracy**, **99.67% Recall**, and **98.78% Precision**.

### 📄 2. Automated Executive PDF Reporting
On-demand PDF generation (`GET /api/reports/pdf`) dynamically aggregates historical logs from the SQLite database.
- Built using ReportLab with a high-end corporate style, corporate metrics summary, and styled, color-coded tables.
- **Self-Healing Design**: The backend automatically checks for the ReportLab library on startup, installing it silently via a sub-process if it is missing.

### 🔔 3. Instant WhatsApp Webhook Alerts
Real-time critical threat notifications are pushed directly to administrators using the WhatsApp CallMeBot API.
- Message payloads use professional markdown layout and custom security emojis:
  - `🚨` **Threat Alert Title** with platform name.
  - `🖥️` **Endpoint Hostname** where execution took place.
  - `☣️` **Threat Specifics** (Process Name and PID).
  - `🔒` **EDR Response Action** (Immediate termination status).
- Automatically falls back to printing rich console logs in air-gapped simulation environments.

### 🔒 4. Remote Endpoint Quarantine Logging
When a critical ransomware process exceeds a **75% risk threshold**:
- The agent terminates the process immediately via kernel handles.
- The Flask backend logs a quarantine directive:
  `🔒 [NETWORK ISOLATION HANDLER]: Host '[hostname]' has been placed in quarantine/isolated status due to critical ransomware execution.`
- Host metadata is isolated in the central SOC to prevent lateral movement.

---

## 📦 PyInstaller Compilation Guide (Production-Grade Agent)

For corporate deployments, running raw `.py` scripts on endpoints is impractical. We compile `agent.py` into a single, windowless executable that starts in milliseconds and runs silently as a background service.

### Step 1: Install PyInstaller
Ensure PyInstaller is installed in your python environment:
```cmd
pip install pyinstaller
```

### Step 2: Bundle Tokenizer & Data Resources
The EDR Agent requires the Keras tokenizer vocabulary cache (`tokenizer.json`) and data sample CSV to run its behavioral simulator when threat keywords are detected. We copy these resource directories into the output bundle.

Run the following command to compile `agent.py` into a silent console-hidden executable:
```cmd
pyinstaller --onefile --noconsole --name=NeuroShieldAgent --add-data "ai_engine/tokenizer.json;ai_engine" --add-data "ai_engine/dynamic_api_call_sequence_per_malware_100_0_306.csv;ai_engine" agent.py
```
*Note for Windows users: The separator is `;` (semicolon). Use `/` (slash) on UNIX-based systems.*

### Step 3: Verify Silent Background Execution
1. Double-click `dist/NeuroShieldAgent.exe`.
2. The agent starts **silently** without opening any terminal window or Command Prompt (leveraging our `ctypes.windll.user32.ShowWindow` background wrapper).
3. Open **Task Manager** -> search for `NeuroShieldAgent.exe`. It runs as a background process consuming **~15 MB RAM**.
4. Check the logs at `C:\ProgramData\NeuroShield\agent.log` to confirm the agent is actively scanning processes.

---

## ⚙️ Deployment & Configuration

### Environment Variables
Configure the platform securely using environment variables. Create a `.env` file at the root or set them in your system environment:

```env
# Flask Backend Configuration
NEUROSHIELD_WHATSAPP_PHONE="+1234567890"  # WhatsApp recipient phone with country code
NEUROSHIELD_WHATSAPP_APIKEY="your_api_key"  # CallMeBot API key

# EDR Agent Configuration
NEUROSHIELD_BACKEND_URL="http://127.0.0.1:5000"
NEUROSHIELD_LOG_PATH="C:\ProgramData\NeuroShield\agent.log"
NEUROSHIELD_MONITOR_INTERVAL="2.0"
NEUROSHIELD_AUTO_TERMINATE="True"
```

### 1. Initialize Flask Backend
```cmd
# Install dependencies
pip install -r requirements.txt

# Start backend server
python app.py
```

### 2. Start the SOC Dashboard
```cmd
cd frontend
npm install
npm run dev
```
Navigate to `http://localhost:3000` to view the dashboard.

### 3. Run the EDR Agent
- **Interactive Console mode**:
  ```cmd
  python agent.py
  ```
- **Silent Background mode**:
  ```cmd
  pythonw agent.py
  ```
- **Service Deployment (SCM)**:
  ```cmd
  python agent.py install
  python agent.py start
  ```

---

## 📄 License
This project is released under the MIT License. Built with ❤️ for enterprise security by **Eng. Abdulrahman Jaber Al-Faifi**.

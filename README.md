# 🛡️ Cyber Sentinel // AI-Powered Cyber Threat Analysis Dashboard

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-00F5FF.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40%2B-FF0055.svg)](https://streamlit.io/)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20v14-8A2BE2.svg)](https://attack.mitre.org/)
[![Lockheed Martin Kill Chain](https://img.shields.io/badge/Cyber%20Kill%20Chain-7%20Stages-00FF66.svg)](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An enterprise-grade, Security Operations Center (SOC) style **AI-Powered Cyber Threat Analysis Dashboard** built in Python and Streamlit. The platform ingests multi-source security telemetry (Apache/Nginx access logs, Windows Sysmon/Security Event logs, raw CSVs, JSON, TXT, and PDF incident reports), detects 17+ cyber threat vectors, runs machine learning anomaly detection via Scikit-learn (Isolation Forest & Random Forest), maps attacks against the **MITRE ATT&CK Enterprise Matrix** and **Lockheed Martin Cyber Kill Chain**, delivers transparent **Explainable AI (XAI)** reasoning, plots an interactive **Global Attack Map**, and produces formal publication-ready incident reports (PDF via ReportLab, Excel via OpenPyXL, CSV, and JSON).

---

## 🌟 Key Features

### 1. 🛡️ Rule & Signature Threat Detection Engine
Detects 17 distinct threat vectors with deep evidence extraction, confidence scoring, and tactical mapping:
* **SQL Injection (SQLi)** (Tautologies, UNION SELECT, stacked drops, time-based blinds)
* **Cross-Site Scripting (XSS)** (Inline scripts, DOM event handlers, SVG/img vectors)
* **Brute Force Attacks** (Sliding-window thresholding on failed logins & Windows Event 4625)
* **Network Port Scanning** (Multi-port probing detection)
* **Directory Traversal / LFI** (`../`, `%2e%2e%2f`, `/etc/passwd`, `win.ini`)
* **Command Injection** (Shell chaining `;`, `&&`, `|`, `whoami`, `cat /etc/shadow`)
* **PowerShell Attacks** (Base64 `-enc`, `-ExecutionPolicy Bypass`, `DownloadString`, `IEX`)
* **Privilege Escalation** (Administrative token assignment, Event 4672, unquoted service bins)
* **Credential Theft** (Mimikatz signatures, LSASS memory dumping, SAM registry exports)
* **Ransomware Indicators** (`vssadmin delete shadows`, mass `.locked` extensions, ransom notes)
* **Reverse Shell Indicators** (`bash -i >& /dev/tcp`, `nc -e`, Python socket spawns)
* **Beaconing Activity** (Periodic external C2 heartbeat pulses with low jitter)
* **Data Exfiltration Patterns** (Mass outbound transfers to staging sites, DNS tunneling)
* **Suspicious URLs & Domains** (DGA algorithms, typosquatting, bare IP endpoints)
* **Malicious IP Addresses** (Tor exit nodes, bulletproof hosting, known C2 servers)

### 2. 🤖 Explainable AI (XAI) Analyst Reasoning Engine
Transforms black-box alert fatigue into transparent SOC analyst explanations:
* **What happened?** Natural language scenario summary.
* **Why was it detected?** Transparent rule triggers, threshold matches, and exact evidence payload snippets.
* **Which log entries caused the detection?** Line-by-line citation.
* **Attacker TTPs:** Step-by-step methodology explaining real-world adversary behavior.
* **Potential Impact:** Infrastructure and data compromise risk.
* **Immediate Containment:** 5-minute emergency mitigation steps.
* **Long-term Remediation:** Architectural hardening and defensive controls.
* **Confidence Percentage:** Deterministic scoring from 70% to 99%.

### 3. 🧬 Malware Analysis Lab
Inspects telemetry across 8 malware families:
* **Trojans** | **Ransomware** | **Spyware** | **Botnets** | **Worms** | **Rootkits** | **Keyloggers** | **Backdoors**
* Displays likelihood percentage, observed behavioral markers, and mitigation playbooks.

### 4. 🎯 MITRE ATT&CK & Cyber Kill Chain Mapping
* **MITRE ATT&CK:** Mapped across Tactics (Initial Access, Execution, Persistence, PrivEsc, Discovery, Exfiltration, Impact) and Technique IDs (T1190, T1110, T1059, T1003, T1486, etc.).
* **Lockheed Martin Cyber Kill Chain:** 7-stage visual tracker highlighting active intrusion depth from *Reconnaissance* to *Actions on Objectives*.

### 5. 🗺️ Global Adversary Attack Map
* Interactive world map powered by **Folium** and CartoDB dark tiles.
* Plots attacker geographical origin, country, city, ISP/ASN, threat severity pin, and attack volume.

### 6. 🤖 Machine Learning Anomaly Detection
* Unsupervised **Isolation Forest** feature extraction (payload length, Shannon entropy, special character ratio, failure status, off-hours execution).
* Detects stealthy zero-day deviations and statistical outliers.

### 7. 💬 AI SOC Copilot (Context-Aware Chatbot)
* Interactive natural language assistant grounded in active telemetry.
* Answers questions like *"Why is 198.51.100.45 suspicious?"*, *"What should I fix first?"*, *"Explain this malware"*, and *"Summarize today's threats"*.

### 8. 📑 Enterprise PDF & Multi-Format Reporting
* **PDF Incident Reports (ReportLab):** Publication-ready document with SOC header, risk gauge, threat breakdown, attack timeline, evidence table, and analyst sign-off.
* **Excel Workbooks (OpenPyXL):** Multi-sheet export with formatted tables and auto-styled headers.
* **CSV & STIX-Compatible JSON:** Machine-readable formats for SIEM ingestion.

---

## 🏗️ Architecture & Directory Structure

```
cyber project/
├── .streamlit/
│   └── config.toml                  # Cyber dark theme (#0B0F19) and server settings
├── assets/
│   └── custom.css                   # Glassmorphic HUD, glowing neon borders, KPI cards
├── data/
│   ├── sample_logs/                 # Pre-generated Apache, Sysmon, and Firewall logs
│   └── threats.db                   # SQLite persistent database
├── modules/
│   ├── __init__.py
│   ├── config.py                    # Taxonomy, MITRE matrix, Kill Chain stages, severity weights
│   ├── database.py                  # Thread-safe SQLite engine, RBAC tables, audit trail
│   ├── authentication.py            # PBKDF2 password hashing with salt, session management
│   ├── upload.py                    # Multi-format parser (Apache/Nginx, Sysmon CSV, JSON, PDF)
│   ├── threat_detection.py          # 17+ detection engines, regex, and heuristic analyzers
│   ├── malware_detection.py         # 8 malware families classification & likelihood engine
│   ├── mitre.py                     # MITRE ATT&CK coverage calculation & matrix tables
│   ├── kill_chain.py                # Lockheed Martin Kill Chain stage progression
│   ├── timeline.py                  # Chronological attack sequence reconstruction
│   ├── risk_engine.py               # Composite weighted risk scoring (0-100) & triage recommendations
│   ├── ml_engine.py                 # Isolation Forest unsupervised anomaly detection
│   ├── threat_intelligence.py       # IoC extraction (IPs, Domains, Hashes) & reputation feeds
│   ├── ai_explainer.py              # SOC Analyst reasoning engine (What, Why, Impact, Mitigation)
│   ├── chatbot.py                   # Context-grounded SOC Copilot
│   ├── attack_map.py                # Folium interactive dark-matter world map
│   ├── charts.py                    # Plotly charts: KPI cards, severity donut, risk gauge
│   ├── report_generator.py          # ReportLab PDF & OpenPyXL Excel export
│   ├── utils.py                     # Sample log generators, logging, and notifications
│   └── dashboard.py                 # Master dashboard view orchestrating HUD & AI drawers
├── tests/
│   ├── __init__.py
│   ├── test_detection.py            # Unit tests for SQLi, XSS, Brute force, Ransomware
│   ├── test_parsers.py              # Unit tests for Apache, Sysmon CSV, and JSON parsers
│   ├── test_risk.py                 # Unit tests for risk score scaling & edge cases
│   ├── test_auth.py                 # Unit tests for password hashing & role enforcement
│   └── test_reports.py              # Unit tests for PDF, Excel, CSV, and JSON generation
├── app.py                           # Main Streamlit application entrypoint
├── requirements.txt                 # Pinned dependencies
└── README.md                        # Enterprise documentation
```

---

## ⚡ Quick Start Installation

### Prerequisites
* **Python 3.12 or 3.13** installed.

### 1. Clone or Open Workspace
```powershell
cd "c:\Users\Ashwin Chikkala\OneDrive\Desktop\cyber project"
```

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Launch the SOC Dashboard
```powershell
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 🔐 Default Access Credentials

The platform includes role-based access control (RBAC):

| Role | Username | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **Lead Administrator** | `admin` | `Admin@12345` | Full system access, User Management, Audit Logs, Clear Database |
| **Security Analyst** | `analyst` | `Analyst@12345` | Ingest Telemetry, Run Scans, Triage Threats, Export Reports |
| **Incident Auditor** | `viewer` | `Viewer@12345` | View-only access to KPIs, Dashboards, and Timeline |

---

## 🧪 Running Automated Unit Tests

Run the complete test suite:
```powershell
python -m unittest discover -s tests -p "test_*.py"
```
All tests validate detection signatures, log parsers, risk scoring algorithms, password hashing, and report compilers.

---

## 📄 License
Released under the **MIT License**. Engineered for production-ready cybersecurity operations and SOC threat hunting.

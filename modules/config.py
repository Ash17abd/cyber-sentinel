"""
Configuration and Taxonomy Module for Cyber Threat Analysis Dashboard.
Defines MITRE ATT&CK mappings, Cyber Kill Chain stages, Threat Classes,
Malware Families, Severity Weights, and System Constants.
"""

from typing import Dict, List, Any
import os
from dotenv import load_dotenv

# Load optional .env file
load_dotenv()

# Base paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.getenv("DATA_DIR", os.path.join(BASE_DIR, "data"))
SAMPLE_LOGS_DIR = os.path.join(DATA_DIR, "sample_logs")
DB_PATH = os.getenv("DB_PATH", os.path.join(DATA_DIR, "threats.db"))
ASSETS_DIR = os.path.join(BASE_DIR, "assets")

# Security & API Secrets from Environment
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ALIENVAULT_OTX_KEY = os.getenv("ALIENVAULT_OTX_KEY", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin@12345")
ANALYST_PASSWORD = os.getenv("ANALYST_PASSWORD", "Analyst@12345")
VIEWER_PASSWORD = os.getenv("VIEWER_PASSWORD", "Viewer@12345")

# Cyber Theme Color Palette
THEME_COLORS = {
    "background": "#0B0F19",
    "surface": "#111827",
    "surface_light": "#1F2937",
    "primary": "#00F5FF",        # Cyan
    "secondary": "#38BDF8",      # Light Blue
    "accent": "#8A2BE2",         # Purple
    "critical": "#FF0055",       # Crimson Red
    "high": "#FF5E00",           # Orange
    "medium": "#FFB703",         # Amber
    "low": "#38BDF8",            # Sky Blue
    "info": "#00FF66",           # Emerald Green
    "text": "#F8FAFC",
    "muted": "#94A3B8"
}

SEVERITY_COLORS = {
    "Critical": THEME_COLORS["critical"],
    "High": THEME_COLORS["high"],
    "Medium": THEME_COLORS["medium"],
    "Low": THEME_COLORS["low"],
    "Info": THEME_COLORS["info"]
}

# Lockheed Martin Cyber Kill Chain Stages (in chronological order)
KILL_CHAIN_STAGES: List[str] = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command & Control",
    "Actions on Objectives"
]

KILL_CHAIN_COLORS = {
    "Reconnaissance": "#38BDF8",
    "Weaponization": "#818CF8",
    "Delivery": "#A78BFA",
    "Exploitation": "#F472B6",
    "Installation": "#FB923C",
    "Command & Control": "#F87171",
    "Actions on Objectives": "#EF4444"
}

# MITRE ATT&CK Enterprise Tactics
MITRE_TACTICS: Dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact"
}

# Core 17 Threat Taxonomy Definitions
THREAT_CATALOG: Dict[str, Dict[str, Any]] = {
    "SQL Injection": {
        "severity": "Critical",
        "mitre_id": "T1190",
        "mitre_technique": "Exploit Public-Facing Application",
        "mitre_tactic": "Initial Access",
        "kill_chain_stage": "Exploitation",
        "description": "Malicious SQL query input crafted to bypass validation and manipulate database backend.",
        "impact": "Unauthorized access, data tampering, leakage of sensitive records, complete database takeover.",
        "mitigation": "Enforce parameterized queries (prepared statements), use ORM, validate/sanitize all inputs, least-privilege DB users."
    },
    "Cross Site Scripting (XSS)": {
        "severity": "High",
        "mitre_id": "T1189",
        "mitre_technique": "Drive-by Compromise",
        "mitre_tactic": "Initial Access",
        "kill_chain_stage": "Delivery",
        "description": "Injection of malicious client-side JavaScript executed within victims' browser sessions.",
        "impact": "Session hijacking, credential harvesting, DOM defacement, unauthorized actions performed on behalf of authenticated users.",
        "mitigation": "Context-aware output encoding, strict Content Security Policy (CSP), HttpOnly cookies, input sanitization."
    },
    "Brute Force Attack": {
        "severity": "High",
        "mitre_id": "T1110",
        "mitre_technique": "Brute Force",
        "mitre_tactic": "Credential Access",
        "kill_chain_stage": "Exploitation",
        "description": "Automated attempts to guess passwords, pins, or authentication tokens across accounts.",
        "impact": "Account compromise, unauthorized administrative access, privilege escalation.",
        "mitigation": "Implement progressive account lockout, CAPTCHA, Multi-Factor Authentication (MFA), rate limiting."
    },
    "Port Scanning": {
        "severity": "Low",
        "mitre_id": "T1046",
        "mitre_technique": "Network Service Discovery",
        "mitre_tactic": "Discovery",
        "kill_chain_stage": "Reconnaissance",
        "description": "Systematic probe of network ports to map active services, daemon versions, and potential entry vectors.",
        "impact": "Network reconnaissance exposing exposed vulnerable services for targeted follow-up exploits.",
        "mitigation": "Deploy stateful firewalls, configure Intrusion Detection Systems (IDS/IPS), close non-essential ports, use fail2ban."
    },
    "Directory Traversal": {
        "severity": "High",
        "mitre_id": "T1006",
        "mitre_technique": "Direct Volume Access",
        "mitre_tactic": "Defense Evasion",
        "kill_chain_stage": "Exploitation",
        "description": "Exploitation of insufficient input filtering using '../' or encoding to access unauthorized server files.",
        "impact": "Arbitrary file disclosure (e.g., /etc/passwd, config files, secret keys, private credentials).",
        "mitigation": "Use secure file access APIs (chroot jail), avoid direct user input in file paths, strictly whitelist allowed file paths."
    },
    "Command Injection": {
        "severity": "Critical",
        "mitre_id": "T1059",
        "mitre_technique": "Command and Scripting Interpreter",
        "mitre_tactic": "Execution",
        "kill_chain_stage": "Exploitation",
        "description": "Injection of arbitrary operating system commands executed through vulnerable application parsers.",
        "impact": "Remote code execution, host system compromise, privilege escalation, lateral pivoting.",
        "mitigation": "Avoid invoking system shells; use safe execution APIs with argument arrays, restrict process capabilities via sandboxing."
    },
    "Malware Indicators": {
        "severity": "Critical",
        "mitre_id": "T1204",
        "mitre_technique": "User Execution: Malicious File",
        "mitre_tactic": "Execution",
        "kill_chain_stage": "Installation",
        "description": "Detection of known malicious file hashes, suspicious executable headers, or payload artifacts.",
        "impact": "Persistent host infection, remote control, keylogging, file destruction or encryption.",
        "mitigation": "Endpoint Detection and Response (EDR), hash-based application whitelisting, automated sandbox detonation."
    },
    "Suspicious URLs": {
        "severity": "Medium",
        "mitre_id": "T1204.001",
        "mitre_technique": "Malicious Link",
        "mitre_tactic": "Execution",
        "kill_chain_stage": "Delivery",
        "description": "Web addresses exhibiting phishing characteristics, redirection chains, or payload hosting paths.",
        "impact": "User redirection to phishing forms, drive-by malware drops, credential intercept.",
        "mitigation": "Web proxy content filtering, automated URL reputation scanning, DNS sinkholing."
    },
    "Suspicious Domains": {
        "severity": "Medium",
        "mitre_id": "T1566.002",
        "mitre_technique": "Spearphishing Link",
        "mitre_tactic": "Initial Access",
        "kill_chain_stage": "Delivery",
        "description": "Domains generated via DGA, typo-squatted, newly registered, or associated with known bulletproof hosts.",
        "impact": "Phishing infrastructure, Command and Control (C2) rendezvous points.",
        "mitigation": "DNS filtering, domain age threshold policies, automated threat intelligence blocklists."
    },
    "Malicious IP Addresses": {
        "severity": "High",
        "mitre_id": "T1071.001",
        "mitre_technique": "Web Protocols C2",
        "mitre_tactic": "Command and Control",
        "kill_chain_stage": "Command & Control",
        "description": "Inbound or outbound traffic with addresses flagged in threat intelligence feeds, Tor exit nodes, or botnets.",
        "impact": "Active remote adversary communication, command reception, exfiltration relay.",
        "mitigation": "Firewall IP blacklisting, geo-blocking, dynamic threat intelligence feed synchronization."
    },
    "Privilege Escalation": {
        "severity": "Critical",
        "mitre_id": "T1068",
        "mitre_technique": "Exploitation for Privilege Escalation",
        "mitre_tactic": "Privilege Escalation",
        "kill_chain_stage": "Exploitation",
        "description": "Suspicious execution of administrative privileges, token impersonation, or sudo exploitation.",
        "impact": "Adversary gains SYSTEM/root authority, bypassing OS security boundaries.",
        "mitigation": "Principle of least privilege, strict sudoers configurations, disable unquoted service paths, patch kernel vulnerabilities."
    },
    "Credential Theft": {
        "severity": "Critical",
        "mitre_id": "T1003",
        "mitre_technique": "OS Credential Dumping",
        "mitre_tactic": "Credential Access",
        "kill_chain_stage": "Actions on Objectives",
        "description": "Access to LSASS process memory, SAM registry hives, Shadow Copies, or NTDS.dit database.",
        "impact": "Harvesting of plain-text passwords and NTLM hashes for network-wide Pass-the-Hash propagation.",
        "mitigation": "Enable Windows Credential Guard, restrict debug privileges (SeDebugPrivilege), run LSA protection."
    },
    "Ransomware Indicators": {
        "severity": "Critical",
        "mitre_id": "T1486",
        "mitre_technique": "Data Encrypted for Impact",
        "mitre_tactic": "Impact",
        "kill_chain_stage": "Actions on Objectives",
        "description": "Rapid mass file modification, shadow copy deletion (vssadmin), known ransomware extensions and ransom notes.",
        "impact": "Irreversible data encryption, operational outage, extortion demands.",
        "mitigation": "Immutable off-site backups, block volume shadow copy deletion commands, EDR behavior ransomware shields."
    },
    "Reverse Shell Indicators": {
        "severity": "Critical",
        "mitre_id": "T1059.004",
        "mitre_technique": "Unix Shell / Remote Shell",
        "mitre_tactic": "Execution",
        "kill_chain_stage": "Command & Control",
        "description": "Outbound interactive command shell pipes to external IP sockets (e.g. bash -i, netcat, python socket).",
        "impact": "Interactive terminal control by remote adversary, complete server compromise.",
        "mitigation": "Strict egress firewall rules, restrict execution of netcat/socat, host-based process monitoring."
    },
    "PowerShell Attacks": {
        "severity": "High",
        "mitre_id": "T1059.001",
        "mitre_technique": "PowerShell Execution",
        "mitre_tactic": "Execution",
        "kill_chain_stage": "Execution",
        "description": "Execution of encoded Base64 commands, bypass execution policy flags, memory injection scripts.",
        "impact": "Fileless malware execution, stealthy discovery, credential harvesting in memory.",
        "mitigation": "Enable PowerShell Script Block Logging (Event 4104), Constrained Language Mode, enforce AppLocker / WDAC."
    },
    "Beaconing Activity": {
        "severity": "High",
        "mitre_id": "T1071",
        "mitre_technique": "Application Layer Protocol",
        "mitre_tactic": "Command and Control",
        "kill_chain_stage": "Command & Control",
        "description": "Periodic outbound network connections with consistent time intervals and jitter indicating C2 check-in.",
        "impact": "Maintained adversary presence, automated waiting state for task execution.",
        "mitigation": "Network traffic analysis (NTA), proxy heartbeat inspection, DNS query frequency analysis."
    },
    "Data Exfiltration Patterns": {
        "severity": "Critical",
        "mitre_id": "T1048",
        "mitre_technique": "Exfiltration Over Alternative Protocol",
        "mitre_tactic": "Exfiltration",
        "kill_chain_stage": "Actions on Objectives",
        "description": "Abnormal volume of outbound data transfers, DNS tunneling requests, or mass archive creation.",
        "impact": "Loss of confidential proprietary data, customer PII exposure, regulatory penalties.",
        "mitigation": "Data Loss Prevention (DLP), egress bandwidth throttling, DNS anomaly inspection, encrypted traffic inspection."
    }
}

# Alias recommendation to mitigation for all catalog entries
for _key, _val in THREAT_CATALOG.items():
    if "mitigation" in _val and "recommendation" not in _val:
        _val["recommendation"] = _val["mitigation"]

# Malware Families Catalog
MALWARE_FAMILIES = {
    "Trojans": {
        "description": "Disguised malicious programs that present themselves as legitimate software to gain access.",
        "indicators": ["rundll32 masquerading", "svchost anomalies", "fake installer names", "embedded resource drops"],
        "severity": "High",
        "mitigation": "Code signing enforcement, EDR binary verification, safe download policies."
    },
    "Ransomware": {
        "description": "Malware that encrypts files and demands payment for the decryption key.",
        "indicators": ["vssadmin delete shadows", "mass file renaming", "known ransom notes (.txt, .html)", "cipher API hooks"],
        "severity": "Critical",
        "mitigation": "Isolated immutable backups, controlled folder access, canary file traps."
    },
    "Spyware": {
        "description": "Surreptitiously monitors user behavior, collects sensitive information, and transmits it externally.",
        "indicators": ["webcam/audio capture API calls", "browser history harvesting", "screen scraping loops"],
        "severity": "High",
        "mitigation": "Anti-spyware scanning, browser extension restrictions, camera/mic permissions hardening."
    },
    "Botnets": {
        "description": "Infected systems connected to a coordinated C2 network awaiting distributed instructions.",
        "indicators": ["IRC/HTTP/DNS C2 beaconing", "DDoS SYN flood bursts", "credential scanning traffic"],
        "severity": "High",
        "mitigation": "Network perimeter filtering, DNS sinkholing, botnet IoC feed blocking."
    },
    "Worms": {
        "description": "Self-replicating malware that spreads across local subnets and network shares without user intervention.",
        "indicators": ["SMB port 445 sweeps", "EternalBlue exploit signatures", "rapid lateral file drops"],
        "severity": "Critical",
        "mitigation": "Disable SMBv1, network microsegmentation, patch remote code execution flaws."
    },
    "Rootkits": {
        "description": "Kernel or driver-level software designed to conceal the existence of certain processes or files.",
        "indicators": ["driver signature bypass", "hooked SSDT tables", "hidden processes from Task Manager"],
        "severity": "Critical",
        "mitigation": "UEFI Secure Boot, Hypervisor-Protected Code Integrity (HVCI), kernel memory integrity."
    },
    "Keyloggers": {
        "description": "Records keystrokes to steal credentials, credit card details, and personal communications.",
        "indicators": ["GetAsyncKeyState API polling", "SetWindowsHookEx calls", "hidden keystroke log buffers"],
        "severity": "High",
        "mitigation": "Virtual on-screen keyboards for sensitive logins, kernel hook monitoring, endpoint anti-keylogger."
    },
    "Backdoors": {
        "description": "Bypasses normal authentication to secure remote, persistent administrative access.",
        "indicators": ["listening high port daemons", "unusual ssh authorized_keys", "scheduled task triggers", "registry Run keys"],
        "severity": "Critical",
        "mitigation": "Regular audit of persistence mechanisms, strict egress firewall, integrity monitoring (FIM)."
    }
}

# Severity Score Weights (for composite risk engine)
SEVERITY_WEIGHTS = {
    "Critical": 25.0,
    "High": 15.0,
    "Medium": 8.0,
    "Low": 2.0,
    "Info": 0.5
}

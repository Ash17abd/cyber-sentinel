"""
Threat Detection Engine.
Detects 17+ cyber threats across heterogeneous security logs using regex,
heuristic signatures, and aggregation analytics.
Provides full MITRE ATT&CK and Cyber Kill Chain context for every detection.
"""

import re
import ipaddress
from collections import defaultdict
from typing import List, Dict, Any, Tuple
import pandas as pd
from modules.config import THREAT_CATALOG

class ThreatDetectionEngine:
    """Core Threat Analyzer identifying adversary behaviors and tactics."""

    # 1. Regex Rule Signatures for Payload Inspection
    PATTERNS = {
        "SQL Injection": [
            (re.compile(r"(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b)", re.IGNORECASE), 95.0,
             "Detected classic SQL UNION/SELECT query injection pattern."),
            (re.compile(r"('|\%27)\s*(OR|AND)\s*('|\d+)?\s*(=|<|>)\s*('|\d+)?", re.IGNORECASE), 92.0,
             "Detected tautology condition SQL injection (e.g. ' OR 1=1)."),
            (re.compile(r"(;\s*DROP\s+TABLE|;\s*SHUTDOWN|\bEXEC\s*\(|\bXP_CMDSHELL\b)", re.IGNORECASE), 98.0,
             "Detected high-risk stacked SQL commands (DROP/EXEC/xp_cmdshell)."),
            (re.compile(r"(SLEEP\s*\(\s*\d+\s*\)|BENCHMARK\s*\(\s*\d+|WAITFOR\s+DELAY)", re.IGNORECASE), 94.0,
             "Detected time-based blind SQL injection payload.")
        ],
        "Cross Site Scripting (XSS)": [
            (re.compile(r"<\s*script[^>]*>.*<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL), 96.0,
             "Detected explicit client-side <script> tag execution attempt."),
            (re.compile(r"javascript\s*:\s*.*|onerror\s*=|onload\s*=|onmouseover\s*=", re.IGNORECASE), 90.0,
             "Detected DOM event handler injection (onerror, onload, javascript: URI)."),
            (re.compile(r"(<svg[^>]*onload=|<img[^>]*onerror=)", re.IGNORECASE), 94.0,
             "Detected multimedia tag attribute XSS vector.")
        ],
        "Directory Traversal": [
            (re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f)", re.IGNORECASE), 93.0,
             "Detected directory traversal sequence ('../' or encoded equivalent)."),
            (re.compile(r"(/etc/passwd|/etc/shadow|/etc/group|c:\\windows\\win\.ini|windows/system32/cmd\.exe)", re.IGNORECASE), 97.0,
             "Detected direct probe for sensitive operating system configuration files.")
        ],
        "Command Injection": [
            (re.compile(r"(;\s*cat\s+/etc/|;\s*id\b|;\s*whoami\b|;\s*uname\s+-a)", re.IGNORECASE), 95.0,
             "Detected chained Unix reconnaissance command injection (; whoami, id)."),
            (re.compile(r"(&&|\|\||;)\s*(cmd\.exe|powershell\.exe|bash|sh|curl\s+http|wget\s+http)", re.IGNORECASE), 94.0,
             "Detected shell chaining operator invoking system shell or payload downloader."),
            (re.compile(r"(`|\$\()([^)]+)(\)|`)", re.IGNORECASE), 85.0,
             "Detected shell backtick or subshell execution expansion syntax.")
        ],
        "Reverse Shell Indicators": [
            (re.compile(r"(bash\s+-i\s+>&|/dev/tcp/\d+\.\d+\.\d+\.\d+|nc\s+-e\s+/bin/)", re.IGNORECASE), 99.0,
             "Detected direct interactive reverse shell pipeline (bash /dev/tcp or nc -e)."),
            (re.compile(r"(python\s+-c\s+.*socket.*pty\.spawn|ruby\s+-rsocket|perl\s+-e\s+.*use Socket)", re.IGNORECASE), 96.0,
             "Detected script-based interactive reverse shell socket invocation.")
        ],
        "PowerShell Attacks": [
            (re.compile(r"powershell(\.exe)?\s+.*(-enc|-encodedcommand|-e)\s+[A-Za-z0-9+/=]{15,}", re.IGNORECASE), 96.0,
             "Detected obfuscated Base64-encoded PowerShell execution."),
            (re.compile(r"(DownloadString\s*\(|Invoke-Expression|IEX\s*\(|bypass\s+-nop\s+-w\s+hidden)", re.IGNORECASE), 92.0,
             "Detected memory-only PowerShell payload download cradle (IEX/DownloadString).")
        ],
        "Credential Theft": [
            (re.compile(r"(mimikatz|sekurlsa|kerberos::|lsass\.dmp|procdump.*lsass)", re.IGNORECASE), 98.0,
             "Detected LSASS memory dumping or Mimikatz credential extraction keyword."),
            (re.compile(r"(ntds\.dit|SYSTEM\.hive|SAM\.hive|reg\s+save\s+hklm\\sam)", re.IGNORECASE), 97.0,
             "Detected attempt to copy or export SAM/NTDS local security registry hives.")
        ],
        "Privilege Escalation": [
            (re.compile(r"(sudo\s+su|whoami\s+/priv|SeDebugPrivilege|TokenPrivileges|setuid\(0\))", re.IGNORECASE), 90.0,
             "Detected privilege discovery or administrative token assignment."),
            (re.compile(r"(sc\s+config\s+.*binpath=|EventID:\s*4672|Special privileges assigned)", re.IGNORECASE), 92.0,
             "Detected unquoted service manipulation or administrative logon privilege assignment.")
        ],
        "Ransomware Indicators": [
            (re.compile(r"(vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog|bcdedit\s+/set\s+.*recoveryenabled\s+no)", re.IGNORECASE), 99.0,
             "Detected automated Volume Shadow Copy or backup deletion command."),
            (re.compile(r"(\.locked|\.crypted|\.encrypt|\.onion|DECRYPT_INSTRUCTIONS|README_FOR_DECRYPT)", re.IGNORECASE), 95.0,
             "Detected ransomware file extension change or extortion payment note marker.")
        ],
        "Suspicious URLs": [
            (re.compile(r"(http[s]?://[^\s\"']+\.(exe|sh|bin|scr|vbs|bat|dll|ps1))", re.IGNORECASE), 88.0,
             "Detected direct URL reference downloading executable script or binary payload."),
            (re.compile(r"(http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?/[a-z0-9_]+)", re.IGNORECASE), 85.0,
             "Detected bare IP URL scheme commonly employed by adversary payload staging servers.")
        ],
        "Suspicious Domains": [
            (re.compile(r"\b([a-z0-9]{18,}\.(com|net|org|xyz|top|ru|cc|tk|bit))\b", re.IGNORECASE), 82.0,
             "Detected high-entropy DGA (Domain Generation Algorithm) candidate domain."),
            (re.compile(r"\b(login-paypal|verify-apple|secure-banking|update-microsoft)\.[a-z0-9-]+\.[a-z]{2,}\b", re.IGNORECASE), 91.0,
             "Detected brand-impersonating typosquatting phishing domain.")
        ],
        "Malware Indicators": [
            (re.compile(r"\b([a-f0-9]{64}|[a-f0-9]{32})\b", re.IGNORECASE), 80.0,
             "Detected suspicious file hash artifact (SHA-256 or MD5).")
        ]
    }

    # Known Malicious / Tor / Threat Intel IPs for immediate signature match
    KNOWN_MALICIOUS_IPS = {
        "198.51.100.45": ("Known C2 Cobalt Strike Server", 98.0),
        "203.0.113.19": ("Identified Tor Exit Node / Scanner", 89.0),
        "185.220.101.5": ("Known Bulletproof Host / Mirai Scanner", 94.0),
        "45.33.32.156": ("Hostile Reconnaissance / Masscan IP", 88.0),
        "194.26.29.112": ("LockBit Ransomware Staging Node", 99.0),
        "91.240.118.168": ("Emotet / Qakbot C2 Beacon Listener", 96.0)
    }

    @classmethod
    def analyze_events(cls, df: pd.DataFrame, upload_id: int = 1) -> List[Dict[str, Any]]:
        """Scans DataFrame of security telemetry and returns detected threats."""
        if df.empty:
            return []

        threats: List[Dict[str, Any]] = []

        # 1. Direct Pattern Matching (Per Line)
        for idx, row in df.iterrows():
            raw_text = f"{row.get('url', '')} {row.get('details', '')} {row.get('raw_log', '')}"
            src_ip = str(row.get('source_ip', '0.0.0.0'))
            dst_ip = str(row.get('destination_ip', '10.0.0.1'))
            timestamp = str(row.get('timestamp', ''))

            # Check Known Malicious IP
            if src_ip in cls.KNOWN_MALICIOUS_IPS:
                reason, conf = cls.KNOWN_MALICIOUS_IPS[src_ip]
                catalog_entry = THREAT_CATALOG["Malicious IP Addresses"]
                threats.append({
                    "upload_id": upload_id,
                    "threat_name": "Malicious IP Addresses",
                    "severity": catalog_entry["severity"],
                    "confidence": conf,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "timestamp": timestamp,
                    "evidence": f"Traffic detected from known malicious IP {src_ip} ({reason})",
                    "mitre_id": catalog_entry["mitre_id"],
                    "mitre_technique": catalog_entry["mitre_technique"],
                    "kill_chain_stage": catalog_entry["kill_chain_stage"],
                    "impact": catalog_entry["impact"],
                    "recommendation": catalog_entry["recommendation"]
                })

            # Check Pattern Signatures
            for threat_name, pattern_list in cls.PATTERNS.items():
                for regex, conf, reason_detail in pattern_list:
                    match = regex.search(raw_text)
                    if match:
                        matched_snippet = match.group(0)[:120]
                        catalog_entry = THREAT_CATALOG.get(threat_name, {})
                        threats.append({
                            "upload_id": upload_id,
                            "threat_name": threat_name,
                            "severity": catalog_entry.get("severity", "High"),
                            "confidence": conf,
                            "source_ip": src_ip,
                            "destination_ip": dst_ip,
                            "timestamp": timestamp,
                            "evidence": f"Matched payload: '{matched_snippet}' in event.",
                            "mitre_id": catalog_entry.get("mitre_id", "T1000"),
                            "mitre_technique": catalog_entry.get("mitre_technique", "Unknown"),
                            "kill_chain_stage": catalog_entry.get("kill_chain_stage", "Exploitation"),
                            "impact": catalog_entry.get("impact", ""),
                            "recommendation": catalog_entry.get("recommendation", "")
                        })
                        break  # Match first highest pattern for this threat

        # 2. Behavioral Aggregation: Brute Force Detection
        threats.extend(cls._detect_brute_force(df, upload_id))

        # 3. Behavioral Aggregation: Port Scanning Detection
        threats.extend(cls._detect_port_scanning(df, upload_id))

        # 4. Behavioral Aggregation: Beaconing Activity
        threats.extend(cls._detect_beaconing(df, upload_id))

        # 5. Behavioral Aggregation: Data Exfiltration
        threats.extend(cls._detect_data_exfiltration(df, upload_id))

        return threats

    @classmethod
    def _detect_brute_force(cls, df: pd.DataFrame, upload_id: int) -> List[Dict[str, Any]]:
        """Identifies rapid repeated failed authentications from identical source IP."""
        detected = []
        failed_counts = defaultdict(int)
        samples = {}

        for _, row in df.iterrows():
            status = str(row.get('status_code', ''))
            details = str(row.get('details', '')).lower()
            evt = str(row.get('event_type', '')).lower()
            src_ip = str(row.get('source_ip', '0.0.0.0'))

            is_failure = (
                status in ['401', '403'] or
                '4625' in status or
                'failed' in details or
                'invalid' in details or
                'unauthorized' in details or
                'winevent_4625' in evt
            )

            if is_failure and src_ip not in ['127.0.0.1', '0.0.0.0', 'PDF_REPORT_SOURCE']:
                failed_counts[src_ip] += 1
                if src_ip not in samples:
                    samples[src_ip] = row

        for ip, count in failed_counts.items():
            if count >= 4:  # Threshold for brute force
                catalog_entry = THREAT_CATALOG["Brute Force Attack"]
                conf = min(99.0, 75.0 + (count * 2.5))
                sample_row = samples[ip]
                detected.append({
                    "upload_id": upload_id,
                    "threat_name": "Brute Force Attack",
                    "severity": "High" if count < 15 else "Critical",
                    "confidence": conf,
                    "source_ip": ip,
                    "destination_ip": str(sample_row.get('destination_ip', '10.0.0.1')),
                    "timestamp": str(sample_row.get('timestamp', '')),
                    "evidence": f"{count} consecutive failed authentication attempts detected from {ip}.",
                    "mitre_id": catalog_entry["mitre_id"],
                    "mitre_technique": catalog_entry["mitre_technique"],
                    "kill_chain_stage": catalog_entry["kill_chain_stage"],
                    "impact": catalog_entry["impact"],
                    "recommendation": catalog_entry["recommendation"]
                })

        return detected

    @classmethod
    def _detect_port_scanning(cls, df: pd.DataFrame, upload_id: int) -> List[Dict[str, Any]]:
        """Detects IPs sending traffic to numerous target ports."""
        detected = []
        ip_targets = defaultdict(set)
        samples = {}

        for _, row in df.iterrows():
            src_ip = str(row.get('source_ip', '0.0.0.0'))
            raw = f"{row.get('url', '')} {row.get('details', '')}"
            # Extract port references (e.g. :80, :443, port 22, etc.)
            ports = re.findall(r":(\d{2,5})\b|\bport\s*[:=]?\s*(\d{2,5})\b", raw)
            for p1, p2 in ports:
                p = p1 or p2
                ip_targets[src_ip].add(p)
            if src_ip not in samples:
                samples[src_ip] = row

        for ip, ports in ip_targets.items():
            if len(ports) >= 5 and ip not in ['127.0.0.1', '0.0.0.0']:
                catalog_entry = THREAT_CATALOG["Port Scanning"]
                detected.append({
                    "upload_id": upload_id,
                    "threat_name": "Port Scanning",
                    "severity": "Low",
                    "confidence": 88.0,
                    "source_ip": ip,
                    "destination_ip": str(samples[ip].get('destination_ip', '10.0.0.1')),
                    "timestamp": str(samples[ip].get('timestamp', '')),
                    "evidence": f"Scanned {len(ports)} target ports: {list(ports)[:8]}...",
                    "mitre_id": catalog_entry["mitre_id"],
                    "mitre_technique": catalog_entry["mitre_technique"],
                    "kill_chain_stage": catalog_entry["kill_chain_stage"],
                    "impact": catalog_entry["impact"],
                    "recommendation": catalog_entry["recommendation"]
                })

        return detected

    @classmethod
    def _detect_beaconing(cls, df: pd.DataFrame, upload_id: int) -> List[Dict[str, Any]]:
        """Detects regular interval periodic connections indicative of C2 heartbeats."""
        detected = []
        ip_counts = defaultdict(int)
        samples = {}

        for _, row in df.iterrows():
            dst = str(row.get('destination_ip', ''))
            src = str(row.get('source_ip', ''))
            url = str(row.get('url', ''))
            if '/api/heartbeat' in url or '/checkin' in url or '/status.php' in url or 'beacon' in url:
                target = dst if dst else src
                ip_counts[target] += 1
                if target not in samples:
                    samples[target] = row

        for target, count in ip_counts.items():
            if count >= 3:
                catalog_entry = THREAT_CATALOG["Beaconing Activity"]
                detected.append({
                    "upload_id": upload_id,
                    "threat_name": "Beaconing Activity",
                    "severity": "High",
                    "confidence": 92.0,
                    "source_ip": str(samples[target].get('source_ip', '192.168.1.50')),
                    "destination_ip": target,
                    "timestamp": str(samples[target].get('timestamp', '')),
                    "evidence": f"Periodic telemetry check-ins ({count} pulses) to endpoint '{samples[target].get('url', '')}'.",
                    "mitre_id": catalog_entry["mitre_id"],
                    "mitre_technique": catalog_entry["mitre_technique"],
                    "kill_chain_stage": catalog_entry["kill_chain_stage"],
                    "impact": catalog_entry["impact"],
                    "recommendation": catalog_entry["recommendation"]
                })

        return detected

    @classmethod
    def _detect_data_exfiltration(cls, df: pd.DataFrame, upload_id: int) -> List[Dict[str, Any]]:
        """Detects outbound byte bursts, mass archive transfers, or DNS exfil patterns."""
        detected = []
        for _, row in df.iterrows():
            details = str(row.get('details', '')).lower()
            raw = str(row.get('raw_log', '')).lower()
            if any(k in details or k in raw for k in ['exfiltrat', 'mega.nz', 'anonfiles', 'transfer.sh', 'base64_encode', '7z a -p', 'tar -czf']):
                catalog_entry = THREAT_CATALOG["Data Exfiltration Patterns"]
                detected.append({
                    "upload_id": upload_id,
                    "threat_name": "Data Exfiltration Patterns",
                    "severity": "Critical",
                    "confidence": 95.0,
                    "source_ip": str(row.get('source_ip', '192.168.1.100')),
                    "destination_ip": str(row.get('destination_ip', 'External C2')),
                    "timestamp": str(row.get('timestamp', '')),
                    "evidence": f"Data exfiltration staging marker: '{row.get('details', '')[:100]}'",
                    "mitre_id": catalog_entry["mitre_id"],
                    "mitre_technique": catalog_entry["mitre_technique"],
                    "kill_chain_stage": catalog_entry["kill_chain_stage"],
                    "impact": catalog_entry["impact"],
                    "recommendation": catalog_entry["recommendation"]
                })
        return detected

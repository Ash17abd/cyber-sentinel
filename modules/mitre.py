"""
MITRE ATT&CK Framework Mapping Module.
Maps detected threats to MITRE ATT&CK Enterprise Tactics, Techniques, IDs,
Mitigations, and Detection Strategies, and generates coverage analytics.
"""

from typing import List, Dict, Any
from collections import defaultdict
import pandas as pd
from modules.config import MITRE_TACTICS

# Comprehensive MITRE ATT&CK Technique Database
MITRE_TECHNIQUE_DETAILS = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries may attempt to exploit a vulnerability or misconfiguration in an Internet-facing computer or program.",
        "mitigation": "Application isolation, network segmentation, regular vulnerability patching, Web Application Firewall (WAF) inspection.",
        "detection_strategy": "Monitor web application access logs for unexpected anomalous request parameters, SQL keywords, and 500 status codes."
    },
    "T1189": {
        "name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.",
        "mitigation": "Content Security Policy (CSP), disabling script execution in browsers, network web proxy filtering.",
        "detection_strategy": "Inspect HTTP response bodies and outgoing proxy logs for suspicious inline script tags or dynamic iframe generation."
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown.",
        "mitigation": "Account lockout policies, multi-factor authentication (MFA), password complexity rules, CAPTCHA on login forms.",
        "detection_strategy": "Monitor Windows Event 4625 (failed logons) and HTTP 401/403 bursts from individual IP addresses."
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts, including port scans.",
        "mitigation": "Perimeter firewalls, disabling unused network daemons, dropping unauthorized inbound ICMP/SYN packets.",
        "detection_strategy": "Analyze firewall and NetFlow logs for sequential or rapid SYN packets sent across a range of ports."
    },
    "T1006": {
        "name": "Direct Volume Access / Path Traversal",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "description": "Adversaries may directly access file storage or traverse directories to bypass OS file access controls.",
        "mitigation": "Strict input validation, path canonicalization, principle of least privilege for application user accounts.",
        "detection_strategy": "Look for URL query strings containing '../' or '%2e%2e' patterns in web server logs."
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "Adversaries may abuse command and script interpreters to execute arbitrary commands, scripts, or binaries.",
        "mitigation": "Execution prevention policies, script-block logging, restricted shell environments.",
        "detection_strategy": "Monitor process creation events (Sysmon Event ID 1) for unexpected child processes spawned by web servers (e.g. w3wp.exe spawning cmd.exe)."
    },
    "T1059.001": {
        "name": "PowerShell Execution",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "Adversaries may abuse PowerShell commands and scripts for fileless execution.",
        "mitigation": "PowerShell Constrained Language Mode, execution policy restriction, disabling PowerShell v2.",
        "detection_strategy": "Enable PowerShell Script Block Logging (Event 4104) and monitor for '-EncodedCommand' or 'DownloadString'."
    },
    "T1059.004": {
        "name": "Unix Shell / Reverse Shell",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "Adversaries may abuse Unix shells to execute interactive commands or pipe sockets.",
        "mitigation": "Egress firewall rules, restricting execution of netcat and socat, removing compilers on production servers.",
        "detection_strategy": "Detect interactive pseudo-terminal invocations linked to remote outbound TCP sockets."
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate access privileges.",
        "mitigation": "Kernel vulnerability patching, principle of least privilege, restricting user sudoers permissions.",
        "detection_strategy": "Audit process creation with elevated tokens and monitor unexpected system service registration."
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries may dump credentials to obtain account login and credential material in the form of hashes.",
        "mitigation": "Enable Windows Credential Guard, run LSA Protection (RunAsPPL), restrict access to SAM and LSASS memory.",
        "detection_strategy": "Monitor Sysmon Event 10 (ProcessAccess) targeting lsass.exe and alerts on procdump or mimikatz syntax."
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "description": "Adversaries may encrypt data on target systems to interrupt availability to system and network resources.",
        "mitigation": "Maintain offline immutable backups, block unauthorized VSS deletions, deploy canary files for rapid alert.",
        "detection_strategy": "Monitor execution of 'vssadmin delete shadows' and rapid file renaming across shared volumes."
    },
    "T1071.001": {
        "name": "Web Protocols C2",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries may communicate using application layer protocols associated with web traffic to evade detection.",
        "mitigation": "Network intrusion detection, SSL/TLS decryption and inspection, threat intelligence IP blacklisting.",
        "detection_strategy": "Inspect outbound HTTP/HTTPS sessions for beaconing periodicity, anomalous headers, and rare user agents."
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "description": "Adversaries may steal data by exfiltrating it over an alternative protocol than the existing command and control channel.",
        "mitigation": "Data Loss Prevention (DLP) filters, blocking unapproved cloud storage providers, egress bandwidth monitoring.",
        "detection_strategy": "Track anomalous surges in outbound traffic volume or unusual high-frequency DNS TXT requests."
    },
    "T1204": {
        "name": "User Execution: Malicious File",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "An adversary may rely on a user executing a malicious file to initiate code execution.",
        "mitigation": "User awareness training, email attachment filtering, application control and endpoint isolation.",
        "detection_strategy": "Monitor email gateway attachments and executable launches originating from user Downloads or Temp folders."
    },
    "T1566.002": {
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries may send spearphishing emails with a malicious link designed to lure victims into clicking.",
        "mitigation": "Anti-spoofing technologies (SPF, DKIM, DMARC), email link rewriting and sandbox inspection.",
        "detection_strategy": "Cross-reference newly observed domain URLs with domain age and reputation feeds."
    }
}

class MitreAttackMapper:
    """Orchestrates MITRE ATT&CK Framework taxonomy mappings and analysis."""

    @staticmethod
    def get_technique_info(technique_id: str) -> Dict[str, Any]:
        """Returns MITRE technique details, or sensible defaults if uncataloged."""
        return MITRE_TECHNIQUE_DETAILS.get(technique_id, {
            "name": f"Technique {technique_id}",
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "description": "Adversary tactic or technique identified in telemetry.",
            "mitigation": "Implement defense-in-depth, endpoint protection, and least-privilege configurations.",
            "detection_strategy": "Monitor security logs, process executions, and network perimeter telemetry."
        })

    @classmethod
    def analyze_mitre_coverage(cls, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculates tactical and technical MITRE ATT&CK coverage statistics."""
        tactic_counts = defaultdict(int)
        technique_counts = defaultdict(int)
        technique_details_list = []

        seen_techniques = set()

        for t in threats:
            tech_id = t.get("mitre_id", "T1000")
            technique_counts[tech_id] += 1
            info = cls.get_technique_info(tech_id)
            tactic = info.get("tactic", "Execution")
            tactic_counts[tactic] += 1

            if tech_id not in seen_techniques:
                seen_techniques.add(tech_id)
                technique_details_list.append({
                    "Technique ID": tech_id,
                    "Technique Name": info.get("name"),
                    "Tactic": tactic,
                    "Mitigation": info.get("mitigation"),
                    "Detection Strategy": info.get("detection_strategy")
                })

        return {
            "tactic_counts": dict(tactic_counts),
            "technique_counts": dict(technique_counts),
            "techniques_table": pd.DataFrame(technique_details_list),
            "total_tactics_triggered": len(tactic_counts),
            "total_techniques_triggered": len(technique_counts)
        }

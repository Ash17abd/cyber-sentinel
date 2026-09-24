"""
AI Explanation Engine for Cyber Threats.
Generates comprehensive, human-like SOC analyst reasoning for any detected threat,
explaining What happened, Why detected, Log entries responsible, Attacker TTPs,
Potential Impact, How to stop it, and Confidence percentage.
"""

from typing import Dict, Any, Optional

# Knowledge Base of Attack Explanations & Methodology
EXPLANATION_KB = {
    "SQL Injection": {
        "what_happened": "An external adversary attempted to inject malicious SQL syntax into application input parameters, intending to manipulate database query execution.",
        "why_detected": "Multiple structured SQL keywords and relational tautologies (e.g. 'UNION SELECT', 'OR 1=1', comment sequences) were identified in input parameters.",
        "attacker_methodology": "Attackers locate unsanitized input fields (such as search boxes, login forms, or URL query strings) and append SQL metacharacters like single quotes (') followed by logic operators to bypass authentication or extract entire table contents.",
        "potential_impact": "Complete relational database exposure, exfiltration of sensitive customer PII/passwords, unauthorized record modification, or remote command execution via database extensions.",
        "how_to_stop_it": "Immediately block the offending source IP at the Web Application Firewall (WAF) and enable WAF SQLi inspection rules.",
        "recommended_mitigation": "Refactor application data access layers to use parameterized queries (Prepared Statements) or secure ORMs. Validate input against strict alphanumeric whitelists."
    },
    "Cross Site Scripting (XSS)": {
        "what_happened": "Malicious client-side script code was submitted to the application, intended to execute within the browsers of other unsuspecting users.",
        "why_detected": "Detected unencoded HTML markup, inline <script> tags, or DOM event handlers (e.g. 'onerror=', 'onload=', 'javascript:') in incoming requests.",
        "attacker_methodology": "Attackers craft payloads that embed malicious JavaScript into web pages viewed by victims. Once executed, the script can access document cookies, session tokens, or simulate user interactions.",
        "potential_impact": "Session hijacking, credential harvesting, unauthorized actions performed under the victim's session, website defacement, and drive-by malware downloads.",
        "how_to_stop_it": "Block incoming requests containing script tags and strip active cookies for affected user sessions.",
        "recommended_mitigation": "Implement context-sensitive output encoding across all templates, enforce strict Content Security Policy (CSP) headers, and set HttpOnly and Secure flags on session cookies."
    },
    "Brute Force Attack": {
        "what_happened": "An automated dictionary or credential stuffing tool was detected attempting rapid successive authentication requests against target user accounts.",
        "why_detected": "High volume of consecutive failed login responses (HTTP 401/403 or Windows Event ID 4625) recorded from a single source IP in a short time window.",
        "attacker_methodology": "Attackers use automated multi-threaded tools (such as Hydra, Medusa, or custom Python scripts) loaded with common password dictionaries or leaked credential lists to systematically guess passwords.",
        "potential_impact": "Unauthorized access to internal accounts, privilege escalation, breach of administrative portals.",
        "how_to_stop_it": "Temporarily block the source IP address on perimeter firewalls and lock targeted accounts after 5 failed attempts.",
        "recommended_mitigation": "Enforce Multi-Factor Authentication (MFA), implement progressive login rate-limiting, CAPTCHA challenges, and IP reputation filtering."
    },
    "Port Scanning": {
        "what_happened": "A network host engaged in systematic port enumeration across multiple services to discover open ports and listening daemon versions.",
        "why_detected": "Rapid sequence of TCP SYN packets sent to numerous distinct destination ports originating from the same source IP.",
        "attacker_methodology": "Adversaries utilize tools like Nmap or Masscan to transmit probe packets to a wide range of ports, determining firewall policies and identifying vulnerable software versions.",
        "potential_impact": "Exposure of unpatched perimeter services, mapping of internal network topology, providing targets for focused exploit payloads.",
        "how_to_stop_it": "Add scanning IP address to edge firewall drop rule; configure fail2ban or automatic IDS blacklisting.",
        "recommended_mitigation": "Disable unnecessary services, restrict management ports (SSH, RDP) to trusted VPN IPs, deploy stateful packet inspection."
    },
    "Directory Traversal": {
        "what_happened": "An adversary attempted to navigate outside the web root directory to view restricted operating system files.",
        "why_detected": "Detection of directory escape sequences ('../', '..\\', '%2e%2e%2f') targeting sensitive paths like '/etc/passwd' or 'win.ini'.",
        "attacker_methodology": "By supplying path traversal characters to file download or view endpoints, adversaries trick application file APIs into opening files from the underlying operating system.",
        "potential_impact": "Leakage of server source code, hardcoded database credentials, cryptographic keys, and system user passwords.",
        "how_to_stop_it": "Reject requests with traversal sequences at the reverse proxy/WAF level.",
        "recommended_mitigation": "Sanitize and canonicalize all file paths using secure APIs; strictly restrict access to a dedicated chroot directory."
    },
    "Command Injection": {
        "what_happened": "Arbitrary operating system shell commands were injected into application parameters and executed by the server host.",
        "why_detected": "Detection of shell command separators (';', '&&', '||', '|') chaining system commands such as 'whoami', 'cat /etc/passwd', or 'id'.",
        "attacker_methodology": "When applications pass untrusted input directly into system shell execution functions (e.g. system(), exec(), popen()), attackers append shell operators to run arbitrary commands.",
        "potential_impact": "Full operating system compromise, interactive shell access, file destruction, lateral movement across the enterprise network.",
        "how_to_stop_it": "Terminate web server processes that have spawned child command shells; isolate server instance from internal network.",
        "recommended_mitigation": "Never invoke OS shells directly. Use language-level APIs that accept argument lists without shell interpretation."
    },
    "PowerShell Attacks": {
        "what_happened": "Adversary invoked PowerShell with evasion flags or Base64 encoded commands to execute memory-only scripts without writing files to disk.",
        "why_detected": "Detection of commandline arguments such as '-EncodedCommand', '-ExecutionPolicy Bypass', 'DownloadString', or 'Invoke-Expression (IEX)'.",
        "attacker_methodology": "Attackers leverage PowerShell's built-in Windows administrative power to download payloads directly into RAM, bypassing traditional signature-based antivirus scanners.",
        "potential_impact": "Fileless malware execution, credential scraping in memory, Active Directory reconnaissance, privilege escalation.",
        "how_to_stop_it": "Terminate offending PowerShell processes via EDR, kill parent process trees, and revoke compromised user session tokens.",
        "recommended_mitigation": "Enable PowerShell Script Block Logging (Event 4104), enforce Constrained Language Mode, and implement Windows Defender Application Control (WDAC)."
    },
    "Ransomware Indicators": {
        "what_happened": "Host exhibited behavioral patterns typical of pre-encryption ransomware activity, including shadow copy deletion and ransom note markers.",
        "why_detected": "Commands attempting backup destruction ('vssadmin delete shadows') or known encrypted file extension changes were logged.",
        "attacker_methodology": "Ransomware operators first dismantle system recovery options by deleting shadow copies and disabling boot recovery, then deploy multi-threaded encryption routines.",
        "potential_impact": "Catastrophic data loss, business operation shutdown, extortion threats.",
        "how_to_stop_it": "IMMEDIATELY disconnect endpoint from network (unplug ethernet / disable WiFi) to halt encryption spread; power off file shares.",
        "recommended_mitigation": "Maintain offline immutable backups, prevent non-admin access to VSS commands, deploy behavioral ransomware protection."
    },
    "Reverse Shell Indicators": {
        "what_happened": "An internal system established an outbound socket connection returning an interactive command shell to an external attacker IP.",
        "why_detected": "Detected shell commands redirecting stdin/stdout across network sockets (e.g., bash -i >& /dev/tcp or netcat reverse pipes).",
        "attacker_methodology": "Because inbound firewall rules often block direct connections, attackers trick compromised servers into initiating outbound connections back to the attacker's listener.",
        "potential_impact": "Direct interactive terminal control of the server by the attacker, allowing data theft and internal pivoting.",
        "how_to_stop_it": "Kill the socket connection with TCP kill, terminate the parent process, and block the remote IP at the egress firewall.",
        "recommended_mitigation": "Restrict outbound egress traffic to only approved ports and protocols; remove unapproved netcat/socat binaries from hosts."
    }
}

class AIExplanationEngine:
    """SOC Analyst reasoning engine providing structured explanations for detections."""

    @classmethod
    def explain_threat(cls, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Generates detailed SOC Analyst reasoning for a given threat dictionary."""
        threat_name = threat.get("threat_name", "Unknown Threat")
        evidence = threat.get("evidence", "No evidence payload recorded.")
        confidence = float(threat.get("confidence", 85.0))

        # Look up baseline explanation knowledge
        base_exp = EXPLANATION_KB.get(threat_name)

        if base_exp:
            what_happened = base_exp["what_happened"]
            why_detected = f"{base_exp['why_detected']} Specifically: {evidence}"
            attacker_methodology = base_exp["attacker_methodology"]
            potential_impact = base_exp["potential_impact"]
            how_to_stop_it = base_exp["how_to_stop_it"]
            recommended_mitigation = base_exp["recommended_mitigation"]
        else:
            # Dynamic synthesis for uncataloged threats
            what_happened = f"Suspicious activity categorized under '{threat_name}' was recorded in system telemetry."
            why_detected = f"Telemetry matched detection signature with evidence: {evidence}"
            attacker_methodology = "Adversaries leverage this technique to advance their intrusion lifecycle and bypass defense mechanisms."
            potential_impact = threat.get("impact") or "Potential compromise of system confidentiality, integrity, or availability."
            how_to_stop_it = f"Isolate source {threat.get('source_ip', 'endpoint')} and block relevant traffic at perimeter firewalls."
            recommended_mitigation = threat.get("recommendation") or "Review logs, apply latest security patches, and enforce least privilege."

        return {
            "threat_name": threat_name,
            "confidence_percentage": f"{int(confidence)}%",
            "confidence_score": confidence,
            "what_happened": what_happened,
            "why_detected": why_detected,
            "log_entries_responsible": evidence,
            "attacker_methodology": attacker_methodology,
            "potential_impact": potential_impact,
            "how_to_stop_it": how_to_stop_it,
            "recommended_mitigation": recommended_mitigation,
            "mitre_technique": threat.get("mitre_technique", "Unknown"),
            "kill_chain_stage": threat.get("kill_chain_stage", "Exploitation")
        }

"""
Risk Score Calculation Engine.
Computes a normalized composite risk score (0-100) combining threat volume,
severity distribution, known malicious IPs, malware family indicators,
and brute-force velocity. Generates prioritized SOC triage recommendations.
"""

from typing import List, Dict, Any, Tuple
import math
from modules.config import SEVERITY_WEIGHTS

class RiskScoreEngine:
    """Calculates enterprise risk index and priority action matrix."""

    @classmethod
    def calculate_risk_score(cls, threats: List[Dict[str, Any]],
                             malware_results: List[Dict[str, Any]] = None,
                             failed_logins: int = 0) -> Dict[str, Any]:
        """Calculates multi-factor composite risk index (0.0 - 100.0)."""
        if not threats and not malware_results:
            return {
                "score": 0.0,
                "level": "Low",
                "color": "#00FF66",
                "breakdown": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
                "factors": {"severity_points": 0, "ip_penalty": 0, "malware_boost": 0, "brute_force_penalty": 0},
                "recommendations": ["No active hostile vectors detected in current telemetry window."]
            }

        malware_results = malware_results or []
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

        raw_score = 0.0
        known_malicious_ips = set()

        for t in threats:
            sev = t.get("severity", "Medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            raw_score += SEVERITY_WEIGHTS.get(sev, 5.0)

            if t.get("threat_name") == "Malicious IP Addresses":
                known_malicious_ips.add(t.get("source_ip"))

        # Factor 1: Known Malicious IP Penalty
        ip_penalty = min(25.0, len(known_malicious_ips) * 12.5)

        # Factor 2: Malware Indicators Boost
        malware_boost = 0.0
        for m in malware_results:
            if m.get("family") == "Ransomware" and m.get("likelihood_value", 0) > 40:
                malware_boost += 25.0
            elif m.get("family") in ["Rootkits", "Backdoors"] and m.get("likelihood_value", 0) > 40:
                malware_boost += 15.0
            elif m.get("likelihood_value", 0) > 50:
                malware_boost += 10.0
        malware_boost = min(35.0, malware_boost)

        # Factor 3: Failed Login / Brute Force Velocity
        brute_penalty = min(20.0, (failed_logins / 5.0) * 4.0)

        # Composite aggregation with logarithmic smoothing to avoid hard clipping
        total_raw = raw_score + ip_penalty + malware_boost + brute_penalty

        # Non-linear scaling formula mapping [0, ~250] to [0, 100]
        if total_raw <= 0:
            final_score = 0.0
        else:
            # 100 * (1 - e^(-total_raw / 65))
            final_score = round(min(100.0, 100.0 * (1.0 - math.exp(-total_raw / 70.0))), 1)

        # Categorize Risk Tier
        if final_score >= 85.0:
            level = "Critical"
            color = "#FF0055"
        elif final_score >= 65.0:
            level = "High"
            color = "#FF5E00"
        elif final_score >= 35.0:
            level = "Medium"
            color = "#FFB703"
        else:
            level = "Low"
            color = "#00FF66"

        # Generate Prioritized Action Recommendations
        recommendations = cls._generate_priorities(threats, malware_results, level)

        return {
            "score": final_score,
            "level": level,
            "color": color,
            "breakdown": severity_counts,
            "factors": {
                "severity_points": round(raw_score, 1),
                "ip_penalty": round(ip_penalty, 1),
                "malware_boost": round(malware_boost, 1),
                "brute_force_penalty": round(brute_penalty, 1)
            },
            "recommendations": recommendations
        }

    @classmethod
    def _generate_priorities(cls, threats: List[Dict[str, Any]],
                             malware_results: List[Dict[str, Any]],
                             level: str) -> List[str]:
        """Formulates top 3-5 prioritized containment steps for incident response."""
        recs = []
        threat_names = {t.get("threat_name") for t in threats}

        if "Ransomware Indicators" in threat_names or any(m.get("family") == "Ransomware" for m in malware_results):
            recs.append("🚨 **P0 IMMEDIATE:** Isolate target host from network immediately to prevent lateral encryption; disconnect backup volumes.")

        if "Credential Theft" in threat_names or "Privilege Escalation" in threat_names:
            recs.append("🔐 **P1 CRITICAL:** Force credential invalidation and Kerberos ticket reset for all accounts observed in telemetry.")

        if "Command Injection" in threat_names or "Reverse Shell Indicators" in threat_names:
            recs.append("🛑 **P1 CRITICAL:** Terminate unauthorized spawned shell processes and block outbound ports at the perimeter firewall.")

        if "SQL Injection" in threat_names:
            recs.append("🛡️ **P2 HIGH:** Apply immediate WAF signature blocking for SQL tautology/UNION payloads and inspect DB query audit logs.")

        if "Brute Force Attack" in threat_names:
            recs.append("⚡ **P2 HIGH:** Enforce dynamic IP rate-limiting and trigger automatic account lockout for repeated failed authentications.")

        if "Port Scanning" in threat_names:
            recs.append("🔍 **P3 MEDIUM:** Blacklist hostile scanning source IPs on external perimeter firewall.")

        if not recs:
            recs.append("✅ **P4 ROUTINE:** Maintain standard SIEM continuous monitoring and audit system logs regularly.")

        return recs[:4]

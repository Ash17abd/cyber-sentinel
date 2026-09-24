"""
Attack Timeline Reconstruction Module.
Builds a chronological narrative of the security incident, ordering events from
Initial Probe -> Reconnaissance -> Scanning -> Initial Access -> Privilege Escalation
-> Persistence -> Data Theft / Impact -> Attack Conclusion.
"""

from typing import List, Dict, Any
from datetime import datetime, timezone
import pandas as pd

class AttackTimelineBuilder:
    """Reconstructs the chronological adversary intrusion path."""

    PHASE_ORDER = [
        "Attack Started",
        "Reconnaissance",
        "Scanning",
        "Initial Access",
        "Privilege Escalation",
        "Persistence",
        "Data Theft",
        "Attack End"
    ]

    @staticmethod
    def map_threat_to_phase(threat_name: str, kill_chain_stage: str) -> str:
        """Determines the chronological attack phase for a given threat."""
        t_low = threat_name.lower()
        if "port scan" in t_low or "recon" in t_low:
            return "Scanning"
        elif "sql injection" in t_low or "xss" in t_low or "brute force" in t_low or "traversal" in t_low:
            return "Initial Access"
        elif "privilege" in t_low or "command injection" in t_low or "powershell" in t_low:
            return "Privilege Escalation"
        elif "backdoor" in t_low or "reverse shell" in t_low or "beacon" in t_low:
            return "Persistence"
        elif "exfiltration" in t_low or "ransomware" in t_low or "credential" in t_low:
            return "Data Theft"
        elif kill_chain_stage == "Reconnaissance":
            return "Reconnaissance"
        elif kill_chain_stage == "Actions on Objectives":
            return "Data Theft"
        return "Initial Access"

    @classmethod
    def build_timeline(cls, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Constructs an ordered list of timeline events with phase metadata."""
        if not threats:
            return []

        # Sort threats by timestamp if valid, else preserve order
        def parse_date(ts: str) -> datetime:
            try:
                return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            except Exception:
                return datetime.now(timezone.utc)

        sorted_threats = sorted(threats, key=lambda x: parse_date(x.get("timestamp", "")))

        timeline = []

        # 1. Attack Started Anchor
        first_t = sorted_threats[0]
        timeline.append({
            "phase": "Attack Started",
            "timestamp": first_t.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "threat_name": "First Hostile Incursion Observed",
            "source_ip": first_t.get("source_ip", "Unknown"),
            "severity": "Info",
            "description": f"Telemetry begins recording suspicious operations originating from {first_t.get('source_ip', 'perimeter')}.",
            "evidence": first_t.get("evidence", "")
        })

        # 2. Add intermediate phases
        for t in sorted_threats:
            phase = cls.map_threat_to_phase(t.get("threat_name", ""), t.get("kill_chain_stage", ""))
            timeline.append({
                "phase": phase,
                "timestamp": t.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "threat_name": t.get("threat_name", "Incident Event"),
                "source_ip": t.get("source_ip", "Unknown"),
                "severity": t.get("severity", "Medium"),
                "description": f"[{phase}] {t.get('threat_name')}: {t.get('impact', '')[:100]}",
                "evidence": t.get("evidence", "")
            })

        # 3. Attack End / Current State Anchor
        last_t = sorted_threats[-1]
        timeline.append({
            "phase": "Attack End",
            "timestamp": last_t.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "threat_name": "Containment Window / Current Telemetry Boundary",
            "source_ip": last_t.get("source_ip", "Unknown"),
            "severity": "Info",
            "description": f"Latest telemetry event captured. SOC containment & triage in progress.",
            "evidence": "Log boundary reached."
        })

        return timeline

    @classmethod
    def to_dataframe(cls, timeline: List[Dict[str, Any]]) -> pd.DataFrame:
        """Converts timeline events to DataFrame for tabular display."""
        if not timeline:
            return pd.DataFrame(columns=["timestamp", "phase", "threat_name", "source_ip", "severity", "description"])
        return pd.DataFrame(timeline)

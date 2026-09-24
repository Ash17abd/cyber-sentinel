"""
Cyber Kill Chain Mapping Module.
Maps attacks across the 7 Lockheed Martin Cyber Kill Chain stages:
Reconnaissance -> Weaponization -> Delivery -> Exploitation -> Installation -> Command & Control -> Actions on Objectives.
Highlights detected stages and measures intrusion progression.
"""

from typing import List, Dict, Any
from collections import defaultdict
from modules.config import KILL_CHAIN_STAGES, KILL_CHAIN_COLORS

class CyberKillChainEngine:
    """Evaluates cyber attack lifecycle progression across Kill Chain stages."""

    STAGE_DESCRIPTIONS = {
        "Reconnaissance": "Adversary researches, identifies and selects targets using network port scans and vulnerability crawlers.",
        "Weaponization": "Adversary packages exploit payloads with malicious remote access Trojans or backdoors.",
        "Delivery": "Transmission of weaponized payload to victim via phishing emails, malicious links, or drive-by web compromise.",
        "Exploitation": "Triggering attacker code on target application or operating system (e.g. SQLi, RCE, directory traversal).",
        "Installation": "Adversary installs backdoor, malware implant, or scheduled persistence mechanism on host.",
        "Command & Control": "Host establishes external two-way C2 communication channel for remote management and commands.",
        "Actions on Objectives": "Adversary achieves end goals: credential harvesting, data exfiltration, or ransomware encryption."
    }

    @classmethod
    def analyze_kill_chain(cls, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculates stage distribution, active states, and maximum intrusion depth."""
        stage_counts = defaultdict(int)
        stage_threats = defaultdict(list)

        for t in threats:
            stage = t.get("kill_chain_stage", "Exploitation")
            if stage in KILL_CHAIN_STAGES:
                stage_counts[stage] += 1
                stage_threats[stage].append(t)
            else:
                stage_counts["Exploitation"] += 1
                stage_threats["Exploitation"].append(t)

        stages_status = []
        max_stage_idx = 0

        for idx, stage_name in enumerate(KILL_CHAIN_STAGES):
            count = stage_counts[stage_name]
            is_active = count > 0
            if is_active and idx > max_stage_idx:
                max_stage_idx = idx

            stages_status.append({
                "stage": stage_name,
                "step_number": idx + 1,
                "is_active": is_active,
                "threat_count": count,
                "color": KILL_CHAIN_COLORS.get(stage_name, "#00F5FF"),
                "description": cls.STAGE_DESCRIPTIONS.get(stage_name, ""),
                "threats": stage_threats[stage_name]
            })

        # Calculate progression score (0 - 100%)
        active_count = sum(1 for s in stages_status if s["is_active"])
        progression_percent = int(((max_stage_idx + 1) / len(KILL_CHAIN_STAGES)) * 100) if active_count > 0 else 0

        return {
            "stages": stages_status,
            "stage_counts": dict(stage_counts),
            "max_active_stage": KILL_CHAIN_STAGES[max_stage_idx] if active_count > 0 else "None",
            "progression_percentage": progression_percent,
            "has_critical_objectives": stage_counts.get("Actions on Objectives", 0) > 0
        }

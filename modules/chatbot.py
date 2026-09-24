"""
AI SOC Chat Assistant (Cyber Copilot).
Interactive context-aware cybersecurity chatbot capable of answering analyst queries
grounded in the active telemetry, detected threats, risk scores, and IoCs.
"""

import re
from typing import List, Dict, Any, Optional

class SOCChatbot:
    """Interactive SOC Analyst Assistant grounded in session context."""

    @classmethod
    def respond(cls, query: str,
                threats: List[Dict[str, Any]],
                risk_data: Dict[str, Any],
                malware_data: List[Dict[str, Any]],
                uploaded_files: List[Dict[str, Any]]) -> str:
        """Processes user natural language query with grounded incident context."""
        q = query.lower().strip()

        # 1. IP Lookup Query (e.g., "Why is 198.51.100.45 suspicious?")
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", q)
        if ip_match:
            ip = ip_match.group(0)
            related_threats = [t for t in threats if t.get("source_ip") == ip or t.get("destination_ip") == ip]
            if related_threats:
                resp = [f"### 🛡️ Telemetry Intelligence for IP `{ip}`:"]
                resp.append(f"**Total Incidents Linked:** {len(related_threats)}\n")
                for t in related_threats[:4]:
                    resp.append(f"- **{t.get('threat_name')}** ({t.get('severity')}) [Confidence: {int(t.get('confidence', 80))}%]")
                    resp.append(f"  *Evidence:* `{t.get('evidence', '')}`")
                    resp.append(f"  *MITRE Technique:* {t.get('mitre_technique')} ({t.get('mitre_id')})")
                resp.append(f"\n**Recommended Action:** Immediately block traffic from `{ip}` on external perimeter firewalls and inspect internal hosts communicating with it.")
                return "\n".join(resp)
            else:
                return f"🔍 **Analysis for IP `{ip}`:** No hostile telemetry or malicious signatures were linked to this IP in the currently uploaded logs. It is currently unflagged in this investigation."

        # 2. Priority / Triage Query ("What should I fix first?", "What to do first?")
        if any(w in q for w in ["fix first", "priority", "what should i do", "remediation", "triage", "next step"]):
            recs = risk_data.get("recommendations", [])
            score = risk_data.get("score", 0.0)
            level = risk_data.get("level", "Low")
            resp = [f"### 🚨 SOC Priority Triage Directive (Current Risk: {score}/100 - {level})"]
            resp.append("Based on multi-factor telemetry analysis, execute the following actions in order:\n")
            for idx, r in enumerate(recs, 1):
                resp.append(f"{idx}. {r}")
            return "\n".join(resp)

        # 3. Summarize Today's Threats ("Summarize today's threats", "Executive summary", "Summary")
        if any(w in q for w in ["summarize", "summary", "overview", "what happened", "report summary"]):
            total = len(threats)
            score = risk_data.get("score", 0.0)
            level = risk_data.get("level", "Low")
            breakdown = risk_data.get("breakdown", {})
            files_count = len(uploaded_files)

            resp = [f"### 📊 Incident Briefing & Threat Summary"]
            resp.append(f"- **Overall Risk Posture:** **{score}/100** ({level} Risk Tier)")
            resp.append(f"- **Total Threats Detected:** **{total}** across {files_count} telemetry file(s)")
            resp.append(f"- **Severity Breakdown:** 🔴 {breakdown.get('Critical', 0)} Critical | 🟠 {breakdown.get('High', 0)} High | 🟡 {breakdown.get('Medium', 0)} Medium | 🔵 {breakdown.get('Low', 0)} Low\n")

            if threats:
                # Top threat types
                from collections import Counter
                counts = Counter([t.get("threat_name") for t in threats])
                top3 = counts.most_common(3)
                resp.append("**Top Observed Attack Vectors:**")
                for name, cnt in top3:
                    resp.append(f"  • **{name}**: {cnt} occurrence(s)")

            if malware_data:
                top_m = malware_data[0]
                resp.append(f"\n**Primary Malware Indicator:** **{top_m.get('family')}** (Likelihood: {top_m.get('likelihood')})")

            return "\n".join(resp)

        # 4. Explain Malware Query ("Explain this malware", "Explain ransomware", "Malware")
        if any(w in q for w in ["malware", "ransomware", "trojan", "botnet", "rootkit", "worm", "backdoor", "keylogger"]):
            if malware_data:
                resp = ["### 🧬 Malware Intelligence Assessment:"]
                for m in malware_data[:3]:
                    resp.append(f"#### **{m.get('family')}** (Likelihood: {m.get('likelihood')} - {m.get('severity')})")
                    resp.append(f"*{m.get('description')}*")
                    resp.append("**Observed Indicators:**")
                    for ind in m.get("indicators", [])[:3]:
                        resp.append(f"- {ind}")
                    resp.append(f"**Mitigation:** {m.get('mitigation')}\n")
                return "\n".join(resp)
            else:
                return "ℹ️ No specific malware family signatures or high-likelihood malware indicators were triggered in the current telemetry set."

        # 5. MITRE ATT&CK Query
        if any(w in q for w in ["mitre", "technique", "tactic"]):
            unique_techs = {f"{t.get('mitre_technique')} ({t.get('mitre_id')})" for t in threats if t.get('mitre_id')}
            if unique_techs:
                resp = ["### 🎯 Observed MITRE ATT&CK Techniques:"]
                for ut in sorted(list(unique_techs))[:8]:
                    resp.append(f"- **{ut}**")
                resp.append("\nNavigate to the **MITRE ATT&CK Matrix** tab in the dashboard for complete technical mapping and defense strategies.")
                return "\n".join(resp)
            return "No MITRE techniques mapped yet. Ingest telemetry logs to view tactical mapping."

        # 6. Default Grounded Response
        return (
            f"🤖 **SOC Copilot:** I have analyzed your telemetry ({len(threats)} detections, Risk Score: {risk_data.get('score', 0)}/100).\n\n"
            f"You can ask me specific questions such as:\n"
            f"- *'Why is IP <address> suspicious?'*\n"
            f"- *'What should I fix first?'*\n"
            f"- *'Summarize today's threats'*\n"
            f"- *'Explain this malware'* or *'Which MITRE techniques were used?'*"
        )

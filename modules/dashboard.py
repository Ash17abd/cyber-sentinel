"""
Main Dashboard View Module.
Coordinates KPI cards, interactive filters, Plotly visualization grids,
threat classification tables, and the AI Explainer deep-dive drawer.
"""

import streamlit as st
import pandas as pd
from typing import List, Dict, Any
from modules.charts import SOCVisualizer
from modules.ai_explainer import AIExplanationEngine
from modules.config import SEVERITY_COLORS

def render_dashboard_view(threats: List[Dict[str, Any]],
                           risk_data: Dict[str, Any],
                           kill_chain_data: Dict[str, Any],
                           mitre_data: Dict[str, Any],
                           timeline_data: List[Dict[str, Any]],
                           uploaded_files: List[Dict[str, Any]],
                           malware_data: List[Dict[str, Any]]) -> None:
    """Renders the comprehensive SOC analyst HUD dashboard."""

    # 1. Cyber Dashboard Header
    st.markdown("""
    <div class="cyber-header">
        <div>
            <h1 class="cyber-title">CYBER SENTINEL // SOC DASHBOARD</h1>
            <div style="color: #94A3B8; font-size: 13px; margin-top: 4px;">
                Active Telemetry HUD • Continuous Threat Detection • Autonomous AI Explainability
            </div>
        </div>
        <div>
            <span class="cyber-badge">STATUS: LIVE MONITORING</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 2. Extract KPI Values
    breakdown = risk_data.get("breakdown", {})
    suspicious_ips = len({t.get("source_ip") for t in threats if t.get("source_ip") not in ["127.0.0.1", "0.0.0.0", "PDF_REPORT_SOURCE"]})

    kpis = {
        "total_files": len(uploaded_files),
        "total_threats": len(threats),
        "critical_threats": breakdown.get("Critical", 0),
        "high_threats": breakdown.get("High", 0),
        "medium_threats": breakdown.get("Medium", 0),
        "low_threats": breakdown.get("Low", 0),
        "malware_indicators": len(malware_data),
        "suspicious_ips": suspicious_ips,
        "risk_score": risk_data.get("score", 0.0),
        "risk_level": risk_data.get("level", "Low"),
        "risk_color": risk_data.get("color", "#00FF66")
    }

    # Render Glowing HTML KPI Cards
    st.markdown(SOCVisualizer.render_kpi_cards_html(kpis), unsafe_allow_html=True)

    # 3. Interactive Filter Controls
    with st.expander("🔍 Telemetry Filters & Search Bar", expanded=False):
        f_col1, f_col2, f_col3 = st.columns(3)
        with f_col1:
            all_sevs = ["Critical", "High", "Medium", "Low", "Info"]
            selected_sevs = st.multiselect("Filter Severity", all_sevs, default=all_sevs)
        with f_col2:
            all_threat_types = sorted(list({t.get("threat_name") for t in threats}))
            selected_threats = st.multiselect("Filter Threat Vector", all_threat_types, default=all_threat_types)
        with f_col3:
            ip_search = st.text_input("Search Source IP / Payload Keyword", placeholder="e.g. 198.51, UNION, powershell")

    # Apply Filters
    filtered_threats = []
    for t in threats:
        if selected_sevs and t.get("severity") not in selected_sevs:
            continue
        if selected_threats and t.get("threat_name") not in selected_threats:
            continue
        if ip_search:
            s_query = ip_search.lower()
            text_pool = f"{t.get('source_ip', '')} {t.get('threat_name', '')} {t.get('evidence', '')}".lower()
            if s_query not in text_pool:
                continue
        filtered_threats.append(t)

    # 4. Primary Chart Grid
    c_col1, c_col2 = st.columns([1, 1])

    with c_col1:
        st.plotly_chart(
            SOCVisualizer.create_risk_gauge(risk_data.get("score", 0.0), risk_data.get("level", "Low")),
            use_container_width=True
        )
        st.plotly_chart(
            SOCVisualizer.create_severity_donut(breakdown),
            use_container_width=True
        )

    with c_col2:
        st.plotly_chart(
            SOCVisualizer.create_kill_chain_chart(kill_chain_data.get("stage_counts", {})),
            use_container_width=True
        )
        # Top threat names
        from collections import Counter
        threat_counts = dict(Counter([t.get("threat_name") for t in threats]))
        st.plotly_chart(
            SOCVisualizer.create_top_threats_bar(threat_counts),
            use_container_width=True
        )

    # 5. Attack Timeline Chart
    st.subheader("⏱️ Attack Sequence Reconstruction Timeline")
    st.plotly_chart(SOCVisualizer.create_timeline_scatter(timeline_data), use_container_width=True)

    # 6. Detailed Threat Telemetry & AI Explainer Drawer
    st.subheader(f"🛡️ Detected Security Incidents ({len(filtered_threats)} Displayed)")
    st.caption("Click any detection card below to inspect the AI Analyst Reasoning, Evidence Snippet, and MITRE Mapping.")

    if not filtered_threats:
        st.info("No threats match your active filter criteria.")
        return

    for idx, threat in enumerate(filtered_threats[:30]):
        sev = threat.get("severity", "Medium")
        color = SEVERITY_COLORS.get(sev, "#38BDF8")
        conf = int(threat.get("confidence", 85))

        header_label = (
            f"[{sev.upper()}] {threat.get('threat_name')} — Source: {threat.get('source_ip')} "
            f"| Confidence: {conf}% | MITRE: {threat.get('mitre_id')}"
        )

        with st.expander(header_label):
            ai_exp = AIExplanationEngine.explain_threat(threat)
            
            exp_col1, exp_col2 = st.columns([2, 1])
            with exp_col1:
                st.markdown(f"**📖 What Happened?**")
                st.write(ai_exp["what_happened"])

                st.markdown(f"**🔍 Why Detected?**")
                st.write(ai_exp["why_detected"])

                st.markdown(f"**💻 Log Evidence Snippet:**")
                st.code(ai_exp["log_entries_responsible"], language="bash")

                st.markdown(f"**🏴‍☠️ Attacker TTP Methodology:**")
                st.write(ai_exp["attacker_methodology"])

            with exp_col2:
                st.markdown(f"""
                <div style="background: rgba(17, 24, 39, 0.8); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 12px; margin-bottom: 12px;">
                    <div style="color: #94A3B8; font-size: 11px;">KILL CHAIN STAGE</div>
                    <div style="color: #00F5FF; font-weight: 700; font-size: 14px;">{threat.get('kill_chain_stage')}</div>
                    <div style="color: #94A3B8; font-size: 11px; margin-top: 8px;">MITRE TECHNIQUE</div>
                    <div style="color: #A855F7; font-weight: 700; font-size: 13px;">{threat.get('mitre_technique')} ({threat.get('mitre_id')})</div>
                    <div style="color: #94A3B8; font-size: 11px; margin-top: 8px;">CONFIDENCE SCORE</div>
                    <div style="color: #00FF66; font-weight: 800; font-size: 18px;">{ai_exp['confidence_percentage']}</div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"**⚠️ Business Impact:**")
                st.write(ai_exp["potential_impact"])

                st.markdown(f"**🛑 Immediate Containment:**")
                st.info(ai_exp["how_to_stop_it"])

                st.markdown(f"**🛡️ Recommended Mitigation:**")
                st.success(ai_exp["recommended_mitigation"])

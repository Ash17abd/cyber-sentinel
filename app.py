"""
AI-Powered Cyber Threat Analysis Dashboard
Main Streamlit Application Entrypoint.
"""

import os
import streamlit as st
import pandas as pd
from streamlit_folium import st_folium

# 1. Page Configuration (Must be first Streamlit command)
st.set_page_config(
    page_title="Cyber Sentinel // SOC AI Threat Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Imports from internal modules
from modules.config import (
    ASSETS_DIR, THREAT_CATALOG, MALWARE_FAMILIES,
    VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, ALIENVAULT_OTX_KEY
)
from modules.database import db
from modules.authentication import (
    init_session_state, render_login_form, get_current_user,
    get_current_role, is_admin, is_analyst, logout_user, render_user_management
)
from modules.upload import FileIngestionEngine
from modules.threat_detection import ThreatDetectionEngine
from modules.malware_detection import MalwareDetectionEngine
from modules.mitre import MitreAttackMapper
from modules.kill_chain import CyberKillChainEngine
from modules.timeline import AttackTimelineBuilder
from modules.risk_engine import RiskScoreEngine
from modules.ml_engine import MLAnomalyEngine
from modules.threat_intelligence import ThreatIntelligenceEngine
from modules.chatbot import SOCChatbot
from modules.attack_map import AttackMapEngine
from modules.charts import SOCVisualizer
from modules.report_generator import IncidentReportGenerator
from modules.utils import SampleDataGenerator, logger
from modules.dashboard import render_dashboard_view

# 3. Load Custom Cyber Dark Theme CSS
def load_custom_css():
    css_path = os.path.join(ASSETS_DIR, "custom.css")
    if os.path.exists(css_path):
        with open(css_path, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_custom_css()
init_session_state()

# 4. Authentication Gate
if not st.session_state.authenticated:
    render_login_form()
    st.stop()

# 5. Initialize Application State
if "threats" not in st.session_state:
    st.session_state.threats = []
if "uploaded_files" not in st.session_state:
    st.session_state.uploaded_files = []
if "combined_df" not in st.session_state:
    st.session_state.combined_df = pd.DataFrame()
if "chat_history" not in st.session_state:
    st.session_state.chat_history = [
        {"role": "assistant", "content": "Greetings, Analyst. I am your autonomous AI SOC Copilot. Ask me to summarize today's threats, investigate suspicious IPs, or recommend triage actions."}
    ]
if "api_keys" not in st.session_state:
    st.session_state.api_keys = {
        "vt": VIRUSTOTAL_API_KEY,
        "abuse": ABUSEIPDB_API_KEY,
        "otx": ALIENVAULT_OTX_KEY
    }

def load_demo_data():
    """Seeds the session with realistic multi-vector cyber telemetry."""
    # Write sample files
    SampleDataGenerator.write_sample_files_to_disk()

    # 1. Apache web attacks
    apache_bytes = SampleDataGenerator.generate_apache_attack_logs().encode('utf-8')
    res1 = FileIngestionEngine.ingest_file("apache_attack_access.log", apache_bytes)

    # 2. Windows Sysmon CSV
    sysmon_bytes = SampleDataGenerator.generate_windows_sysmon_csv().encode('utf-8')
    res2 = FileIngestionEngine.ingest_file("windows_sysmon_events.csv", sysmon_bytes)

    # 3. Firewall JSON
    fw_bytes = SampleDataGenerator.generate_json_firewall_logs().encode('utf-8')
    res3 = FileIngestionEngine.ingest_file("firewall_network_events.json", fw_bytes)

    dfs = [res1["events_df"], res2["events_df"], res3["events_df"]]
    st.session_state.combined_df = pd.concat(dfs, ignore_index=True)
    st.session_state.uploaded_files = [res1, res2, res3]

    # Run detection
    detected = ThreatDetectionEngine.analyze_events(st.session_state.combined_df, upload_id=1)
    st.session_state.threats = detected
    user_callsign = st.session_state.get("username") or "SYSTEM"
    db.log_audit(user_callsign, "LOAD_DEMO_DATA", "Loaded enterprise demo threat telemetry.")

# Auto-seed demo data on first load if empty
if not st.session_state.threats and not st.session_state.uploaded_files:
    load_demo_data()

# 6. Global Analytics Computations
all_text = " ".join([str(r.get("raw_log", "")) + " " + str(r.get("details", "")) for _, r in st.session_state.combined_df.iterrows()]) if not st.session_state.combined_df.empty else ""
malware_results = MalwareDetectionEngine.analyze_malware(st.session_state.combined_df)
risk_data = RiskScoreEngine.calculate_risk_score(st.session_state.threats, malware_results)
kill_chain_data = CyberKillChainEngine.analyze_kill_chain(st.session_state.threats)
mitre_data = MitreAttackMapper.analyze_mitre_coverage(st.session_state.threats)
timeline_data = AttackTimelineBuilder.build_timeline(st.session_state.threats)

# 7. Sidebar Navigation & Personnel Status
with st.sidebar:
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 16px;">
        <span style="font-size: 28px;">🛡️</span>
        <div>
            <div style="color: #00F5FF; font-weight: 800; font-size: 16px; letter-spacing: -0.5px;">CYBER SENTINEL</div>
            <div style="color: #94A3B8; font-size: 11px;">AI SOC Operations HUD</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    user_info = get_current_user() or {}
    role = get_current_role() or "Viewer"
    st.markdown(f"""
    <div style="background: rgba(17, 24, 39, 0.7); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 10px; margin-bottom: 16px;">
        <div style="font-size: 11px; color: #94A3B8;">AUTHENTICATED CALL-SIGN</div>
        <div style="font-weight: 700; color: #F8FAFC; font-size: 13px;">{user_info.get('full_name') or user_info.get('username', 'Analyst')}</div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px;">
            <span class="severity-pill severity-info">{role}</span>
            <span style="color: #00FF66; font-size: 11px;">● Online</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    menu_options = [
        "📊 SOC Dashboard",
        "📂 Telemetry Ingestion",
        "🔍 Threat Intelligence (IoCs)",
        "🧬 Malware Analysis Lab",
        "🎯 MITRE ATT&CK Matrix",
        "⚡ Cyber Kill Chain",
        "🗺️ Global Attack Map",
        "🤖 ML Anomaly Lab",
        "💬 AI SOC Copilot",
        "📑 Incident Reports & Export",
        "⚙️ Admin & Audit Logs"
    ]

    selected_page = st.radio("Navigation Menu", menu_options, index=0)

    st.markdown("---")
    c_btn1, c_btn2 = st.columns(2)
    with c_btn1:
        if st.button("🚀 Demo Data", use_container_width=True, help="Reload sample attack telemetry"):
            load_demo_data()
            st.success("Telemetry refreshed!")
            st.rerun()
    with c_btn2:
        if st.button("🚪 Logout", use_container_width=True):
            logout_user()

    st.caption("Cyber Sentinel v1.0.0 Enterprise • MITRE v14 • Kill Chain Ready")

# 8. View Routing

# --- PAGE 1: SOC DASHBOARD ---
if selected_page == "📊 SOC Dashboard":
    # Critical Alert Popup Banner if Critical Threats exist
    crit_count = risk_data.get("breakdown", {}).get("Critical", 0)
    if crit_count > 0:
        st.markdown(f"""
        <div style="background: rgba(255, 0, 85, 0.15); border: 1px solid #FF0055; border-radius: 8px; padding: 12px 18px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center;" class="alert-pulse">
            <div>
                <span style="color: #FF0055; font-weight: 800; font-size: 14px;">🚨 CRITICAL INCIDENTS ACTIVE ({crit_count})</span>
                <span style="color: #F8FAFC; font-size: 12px; margin-left: 10px;">Immediate adversary containment required. Check priority triage directives.</span>
            </div>
            <span class="severity-pill severity-critical">SEV-1 ACTIVE</span>
        </div>
        """, unsafe_allow_html=True)

    render_dashboard_view(
        st.session_state.threats,
        risk_data,
        kill_chain_data,
        mitre_data,
        timeline_data,
        st.session_state.uploaded_files,
        malware_results
    )

# --- PAGE 2: TELEMETRY INGESTION ---
elif selected_page == "📂 Telemetry Ingestion":
    st.subheader("📂 Multi-Source Security Telemetry Ingestion")
    st.caption("Upload raw web logs, Windows Sysmon CSVs, JSON network feeds, TXT logs, or PDF Incident Reports.")

    upload_col1, upload_col2 = st.columns([2, 1])

    with upload_col1:
        uploaded_files = st.file_uploader(
            "Select one or multiple security telemetry files",
            type=["csv", "json", "log", "txt", "pdf"],
            accept_multiple_files=True
        )

        if st.button("⚡ Ingest & Analyze Uploaded Files", type="primary", use_container_width=True):
            if uploaded_files:
                new_events = []
                file_summaries = []

                for uf in uploaded_files:
                    f_bytes = uf.read()
                    res = FileIngestionEngine.ingest_file(uf.name, f_bytes)
                    new_events.append(res["events_df"])
                    file_summaries.append(res)

                    # Log to database
                    db.log_upload(
                        filename=res["filename"],
                        file_type=res["file_type"],
                        file_size=res["file_size"],
                        file_hash=res["file_hash"],
                        uploaded_by=st.session_state.username,
                        records_count=res["records_count"]
                    )

                st.session_state.combined_df = pd.concat(new_events, ignore_index=True)
                st.session_state.uploaded_files = file_summaries

                # Run threat detection
                detected = ThreatDetectionEngine.analyze_events(st.session_state.combined_df)
                st.session_state.threats = detected
                db.save_detected_threats(detected)
                db.log_audit(st.session_state.username, "UPLOAD_FILES", f"Ingested {len(uploaded_files)} files ({len(detected)} threats detected).")

                st.success(f"Successfully processed {len(uploaded_files)} files! Identified {len(detected)} potential security threats.")
                st.rerun()
            else:
                st.warning("Please upload at least one file or use the 'Load Demo Data' button.")

    with upload_col2:
        st.markdown("""
        <div style="background: rgba(17, 24, 39, 0.7); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 14px;">
            <h4 style="color: #00F5FF; margin-top: 0;">Supported Formats</h4>
            <p style="font-size: 12px; color: #94A3B8; margin-bottom: 6px;">• <b>Apache / Nginx:</b> Combined & error access logs</p>
            <p style="font-size: 12px; color: #94A3B8; margin-bottom: 6px;">• <b>Windows Events:</b> Sysmon / Security log CSVs</p>
            <p style="font-size: 12px; color: #94A3B8; margin-bottom: 6px;">• <b>JSON / NDJSON:</b> Arbitrary SIEM JSON feeds</p>
            <p style="font-size: 12px; color: #94A3B8; margin-bottom: 6px;">• <b>PDF:</b> Threat intelligence briefs & reports</p>
            <p style="font-size: 12px; color: #94A3B8;">• <b>CSV / TXT:</b> Firewall & authentication logs</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("📋 Ingested Telemetry Records")
    if not st.session_state.combined_df.empty:
        st.dataframe(
            st.session_state.combined_df[["timestamp", "source_ip", "destination_ip", "event_type", "details"]].head(100),
            use_container_width=True
        )
    else:
        st.info("No telemetry logs currently loaded.")

# --- PAGE 3: THREAT INTELLIGENCE (IOCs) ---
elif selected_page == "🔍 Threat Intelligence (IoCs)":
    st.subheader("🔍 Threat Intelligence & Indicator Enrichment")
    st.caption("Extracted network and host Indicators of Compromise (IoCs) cross-referenced against global reputation feeds.")

    # API Keys Configuration drawer
    with st.expander("🔑 Threat Intelligence API Keys (Optional)", expanded=False):
        c1, c2, c3 = st.columns(3)
        with c1:
            st.session_state.api_keys["vt"] = st.text_input("VirusTotal API Key", type="password", value=st.session_state.api_keys["vt"])
        with c2:
            st.session_state.api_keys["abuse"] = st.text_input("AbuseIPDB API Key", type="password", value=st.session_state.api_keys["abuse"])
        with c3:
            st.session_state.api_keys["otx"] = st.text_input("AlienVault OTX Key", type="password", value=st.session_state.api_keys["otx"])
        st.caption("If no keys are provided, the system utilizes high-fidelity offline cached threat intelligence.")

    # Harvest IoCs
    iocs = ThreatIntelligenceEngine.extract_all_iocs(all_text)

    t1, t2, t3, t4, t5 = st.tabs([
        f"IPv4 Addresses ({len(iocs['ips'])})",
        f"Domains ({len(iocs['domains'])})",
        f"Suspicious URLs ({len(iocs['urls'])})",
        f"File Hashes ({len(iocs['hashes'])})",
        f"Email Addresses ({len(iocs['emails'])})"
    ])

    with t1:
        st.write("#### Extracted External & Internal IP Telemetry")
        for ip in iocs['ips'][:15]:
            rep = ThreatIntelligenceEngine.lookup_ip_reputation(
                ip,
                st.session_state.api_keys["vt"],
                st.session_state.api_keys["abuse"]
            )
            score = rep.get("score", 0)
            badge_color = "#FF0055" if score >= 80 else ("#FF5E00" if score >= 50 else "#00FF66")

            st.markdown(f"""
            <div style="background: rgba(17, 24, 39, 0.7); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 12px; margin-bottom: 8px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-family: 'JetBrains Mono'; font-weight: bold; font-size: 15px; color: #00F5FF;">{ip}</span>
                    <span style="background: rgba(255,255,255,0.1); border: 1px solid {badge_color}; color: {badge_color}; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">
                        {rep.get('reputation')} ({score}% Threat Score)
                    </span>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; margin-top: 8px; font-size: 12px; color: #94A3B8;">
                    <div><b>Origin:</b> {rep.get('country')} ({rep.get('asn')})</div>
                    <div><b>VirusTotal:</b> {rep.get('virustotal')}</div>
                    <div><b>AbuseIPDB:</b> {rep.get('abuseipdb')}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

    with t2:
        st.write("#### Discovered Domains")
        if iocs['domains']:
            for d in iocs['domains']:
                st.write(f"- `{d}`")
        else:
            st.info("No standalone domain IoCs extracted.")

    with t3:
        st.write("#### Extracted Web URLs")
        if iocs['urls']:
            for u in iocs['urls']:
                st.code(u, language="bash")
        else:
            st.info("No URLs extracted.")

    with t4:
        st.write("#### Identified File Hashes (SHA-256 / MD5)")
        if iocs['hashes']:
            for h in iocs['hashes']:
                st.code(h, language="text")
        else:
            st.info("No file hashes detected.")

    with t5:
        st.write("#### Harvested Email Addresses")
        if iocs['emails']:
            for e in iocs['emails']:
                st.write(f"- `{e}`")
        else:
            st.info("No email addresses detected.")

# --- PAGE 4: MALWARE ANALYSIS LAB ---
elif selected_page == "🧬 Malware Analysis Lab":
    st.subheader("🧬 Malware Signature & Family Classification Lab")
    st.caption("Deep behavioral inspection across 8 core malware classes: Trojans, Ransomware, Spyware, Botnets, Worms, Rootkits, Keyloggers, Backdoors.")

    if not malware_results:
        st.info("No explicit malware behavioral signatures triggered in the current telemetry window.")
    else:
        for m in malware_results:
            likelihood = m["likelihood_value"]
            sev = m["severity"]
            bar_color = "#FF0055" if likelihood >= 70 else ("#FF5E00" if likelihood >= 40 else "#00F5FF")

            with st.container():
                st.markdown(f"""
                <div style="background: rgba(17, 24, 39, 0.85); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 10px; padding: 18px; margin-bottom: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <div>
                            <span style="font-size: 18px; font-weight: 800; color: #F8FAFC;">{m['family']}</span>
                            <span class="severity-pill severity-{sev.lower()}" style="margin-left: 8px;">{sev}</span>
                        </div>
                        <div style="font-size: 22px; font-weight: 800; color: {bar_color}; font-family: 'JetBrains Mono';">
                            {m['likelihood']} LIKELIHOOD
                        </div>
                    </div>
                    <p style="color: #94A3B8; font-size: 13px; margin: 4px 0 12px 0;">{m['description']}</p>
                    <div style="background: rgba(11, 15, 25, 0.7); border-radius: 6px; padding: 10px; margin-bottom: 10px;">
                        <span style="color: #00F5FF; font-weight: 600; font-size: 12px;">Triggered Behavioral Indicators:</span>
                        <ul style="margin: 4px 0 0 0; padding-left: 20px; font-size: 12px; color: #E2E8F0;">
                            {''.join([f"<li>{ind}</li>" for ind in m['indicators']])}
                        </ul>
                    </div>
                    <div style="color: #00FF66; font-size: 12px;"><b>Recommended Countermeasure:</b> {m['mitigation']}</div>
                </div>
                """, unsafe_allow_html=True)

# --- PAGE 5: MITRE ATT&CK MATRIX ---
elif selected_page == "🎯 MITRE ATT&CK Matrix":
    st.subheader("🎯 MITRE ATT&CK Enterprise Framework Mapping")
    st.caption("Tactical mapping of all detected attack techniques against the MITRE ATT&CK Enterprise Matrix.")

    m_col1, m_col2 = st.columns([1, 1])
    with m_col1:
        st.plotly_chart(SOCVisualizer.create_mitre_tactic_bar(mitre_data.get("tactic_counts", {})), use_container_width=True)
    with m_col2:
        st.markdown(f"""
        <div style="background: rgba(17, 24, 39, 0.8); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 18px;">
            <h4 style="color: #00F5FF; margin-top: 0;">MITRE Coverage Summary</h4>
            <div style="display: flex; gap: 24px; margin-bottom: 12px;">
                <div>
                    <div style="color: #94A3B8; font-size: 11px;">TACTICS TRIGGERED</div>
                    <div style="font-size: 28px; font-weight: 800; color: #F8FAFC;">{mitre_data.get('total_tactics_triggered', 0)}</div>
                </div>
                <div>
                    <div style="color: #94A3B8; font-size: 11px;">TECHNIQUES IDENTIFIED</div>
                    <div style="font-size: 28px; font-weight: 800; color: #38BDF8;">{mitre_data.get('total_techniques_triggered', 0)}</div>
                </div>
            </div>
            <p style="color: #94A3B8; font-size: 12px;">
                Adversary techniques are actively monitored across Initial Access, Execution, Persistence, Privilege Escalation, Credential Access, Discovery, and Impact.
            </p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("📋 Active MITRE Technique Catalog")
    if not mitre_data.get("techniques_table").empty:
        st.dataframe(mitre_data.get("techniques_table"), use_container_width=True)
    else:
        st.info("No MITRE techniques triggered.")

# --- PAGE 6: CYBER KILL CHAIN ---
elif selected_page == "⚡ Cyber Kill Chain":
    st.subheader("⚡ Lockheed Martin Cyber Kill Chain Progression")
    st.caption("Visualizing adversary intrusion depth across the 7 attack lifecycle stages.")

    kc_stages = kill_chain_data.get("stages", [])
    max_stage = kill_chain_data.get("max_active_stage")
    progression = kill_chain_data.get("progression_percentage", 0)

    st.markdown(f"""
    <div style="background: rgba(17, 24, 39, 0.85); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 10px; padding: 16px; margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span style="font-weight: 700; color: #F8FAFC;">INTRUSION LIFECYCLE DEPTH: <span style="color: #00F5FF;">{max_stage.upper()}</span></span>
            <span style="font-family: 'JetBrains Mono'; font-weight: 800; color: {'#FF0055' if progression >= 70 else '#FFB703'};">{progression}% LIFECYCLE COMPLETED</span>
        </div>
        <div style="background: #1F2937; height: 10px; border-radius: 9999px; overflow: hidden;">
            <div style="background: linear-gradient(90deg, #00F5FF 0%, #FF0055 100%); width: {progression}%; height: 100%;"></div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Render each stage cards
    for s in kc_stages:
        status_badge = "ACTIVE DETECTIONS" if s["is_active"] else "DORMANT / UNTRIGGERED"
        badge_cls = "severity-critical" if s["is_active"] else "severity-low"

        with st.expander(f"Stage {s['step_number']}: {s['stage']} — [{s['threat_count']} Events]", expanded=s["is_active"]):
            st.markdown(f"*{s['description']}*")
            if s["is_active"]:
                st.write("**Observed Threats in this Stage:**")
                for st_t in s["threats"][:5]:
                    st.write(f"- **{st_t.get('threat_name')}** ({st_t.get('severity')}) from `{st_t.get('source_ip')}`")
            else:
                st.caption("No indicators observed at this Kill Chain checkpoint.")

# --- PAGE 7: GLOBAL ATTACK MAP ---
elif selected_page == "🗺️ Global Attack Map":
    map_head1, map_head2 = st.columns([2, 1])
    with map_head1:
        st.subheader("🗺️ Global Adversary Infrastructure & Geolocation Map")
        st.caption("Real-time geographic visualization of adversary origins, country, city, ISP, and threat levels.")
    with map_head2:
        map_style_choice = st.radio(
            "Basemap Style",
            ["🌑 Cyber Dark (Esri Canvas)", "🌐 OpenStreetMap (Full Detail)", "🛰️ Satellite Imagery"],
            horizontal=True
        )

    style_key = "cyber_dark"
    if "OpenStreetMap" in map_style_choice:
        style_key = "osm"
    elif "Satellite" in map_style_choice:
        style_key = "satellite"

    try:
        map_obj, df_geo = AttackMapEngine.generate_map(st.session_state.threats, map_style=style_key)
    except TypeError:
        map_obj, df_geo = AttackMapEngine.generate_map(st.session_state.threats)
    st_folium(map_obj, width="100%", height=560, returned_objects=[])

    st.markdown("---")
    st.subheader("🌐 Geographic Origin Breakdown")
    if not df_geo.empty:
        st.dataframe(df_geo, use_container_width=True)
    else:
        st.info("No external routable IP addresses detected in current telemetry.")

# --- PAGE 8: ML ANOMALY LAB ---
elif selected_page == "🤖 ML Anomaly Lab":
    st.subheader("🤖 Machine Learning Anomaly Detection Lab")
    st.caption("Unsupervised Isolation Forest algorithm detecting stealthy zero-day deviations, off-hours anomalies, and payload entropy.")

    c_rate = st.slider("Anomaly Contamination Threshold (%)", min_value=5, max_value=25, value=12, step=1)
    
    with st.spinner("Extracting multi-dimensional feature vectors & training Isolation Forest..."):
        ml_results = MLAnomalyEngine.run_anomaly_detection(st.session_state.combined_df, contamination=(c_rate / 100.0))

    col_m1, col_m2 = st.columns([1, 2])
    with col_m1:
        st.markdown(f"""
        <div style="background: rgba(17, 24, 39, 0.85); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 18px;">
            <h4 style="color: #00F5FF; margin-top: 0;">Model Diagnostics</h4>
            <div style="color: #94A3B8; font-size: 12px; margin-bottom: 4px;">ALGORITHM</div>
            <div style="font-weight: 700; color: #F8FAFC;">Isolation Forest (100 Trees)</div>
            <div style="color: #94A3B8; font-size: 12px; margin-top: 10px;">ANOMALIES FLAGGED</div>
            <div style="font-size: 32px; font-weight: 800; color: #FF0055;">{ml_results['anomalies_detected']}</div>
            <div style="color: #94A3B8; font-size: 12px; margin-top: 10px;">TELEMETRY EVALUATED</div>
            <div style="font-size: 18px; font-weight: 700; color: #38BDF8;">{ml_results.get('total_analyzed', 0)} Records</div>
        </div>
        """, unsafe_allow_html=True)

    with col_m2:
        st.write("#### Identified Behavioral Anomalies")
        if ml_results["anomalies_list"]:
            for anom in ml_results["anomalies_list"][:10]:
                st.markdown(f"""
                <div style="background: rgba(15, 23, 42, 0.7); border-left: 3px solid #FF0055; border-radius: 6px; padding: 10px 14px; margin-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between;">
                        <span style="font-weight: bold; color: #F8FAFC;">Source: <code>{anom['source_ip']}</code></span>
                        <span style="color: #FF0055; font-weight: bold; font-family: 'JetBrains Mono';">Confidence: {anom['confidence']}</span>
                    </div>
                    <div style="font-size: 12px; color: #94A3B8; margin-top: 4px;"><b>Indicators:</b> {anom['behavioral_flags']}</div>
                    <div style="font-size: 11px; color: #38BDF8; font-family: 'JetBrains Mono'; margin-top: 4px;">{anom['log_snippet']}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No statistical outliers detected above the sensitivity threshold.")

# --- PAGE 9: AI SOC COPILOT (CHATBOT) ---
elif selected_page == "💬 AI SOC Copilot":
    st.subheader("💬 AI SOC Analyst Assistant (Autonomous Copilot)")
    st.caption("Interactive cybersecurity assistant grounded in your active telemetry, threat detections, and risk scores.")

    # Render Chat History
    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Chat Input
    user_prompt = st.chat_input("Ask a question about the active telemetry (e.g. 'Why is 198.51.100.45 suspicious?', 'What should I fix first?')")
    if user_prompt:
        # Add user query to history
        st.session_state.chat_history.append({"role": "user", "content": user_prompt})
        with st.chat_message("user"):
            st.markdown(user_prompt)

        # Generate grounded response
        with st.chat_message("assistant"):
            bot_reply = SOCChatbot.respond(
                user_prompt,
                st.session_state.threats,
                risk_data,
                malware_results,
                st.session_state.uploaded_files
            )
            st.markdown(bot_reply)
            st.session_state.chat_history.append({"role": "assistant", "content": bot_reply})

# --- PAGE 10: INCIDENT REPORTS & EXPORT ---
elif selected_page == "📑 Incident Reports & Export":
    st.subheader("📑 Formal Incident Response Reports & Data Export")
    st.caption("Generate publication-ready PDF Incident Reports, multi-tab Excel workbooks, or RFC-compliant CSV & JSON feeds.")

    rep_col1, rep_col2 = st.columns([1, 1])

    with rep_col1:
        st.markdown("""
        <div style="background: rgba(17, 24, 39, 0.85); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 10px; padding: 20px;">
            <h4 style="color: #00F5FF; margin-top: 0;">📄 Generate Formal PDF Incident Report</h4>
            <p style="color: #94A3B8; font-size: 12px;">
                Generates an executive-level PDF report via ReportLab complete with Executive Summary,
                Risk Gauge, Threat Severity Breakdown, Attack Timeline, Evidence Snippets, and Remediation Roadmap.
            </p>
        </div>
        """, unsafe_allow_html=True)

        analyst_notes_input = st.text_area("Lead Analyst Investigation Notes", placeholder="Enter official SOC observations, containment remarks, or escalation instructions...")

        if st.button("📥 Compile & Download Official PDF Report", type="primary", use_container_width=True):
            with st.spinner("Compiling publication-ready PDF Incident Report via ReportLab..."):
                pdf_bytes = IncidentReportGenerator.generate_pdf_report(
                    st.session_state.threats,
                    risk_data,
                    mitre_data,
                    timeline_data,
                    analyst_name=st.session_state.get("username", "SOC Analyst"),
                    analyst_notes=analyst_notes_input
                )
                report_code = IncidentReportGenerator.generate_report_code()
                db.save_incident_report({
                    "report_code": report_code,
                    "title": "Autonomous SOC Incident Report",
                    "generated_by": st.session_state.username,
                    "risk_score": risk_data.get("score", 0.0),
                    "threat_count": len(st.session_state.threats),
                    "critical_count": risk_data.get("breakdown", {}).get("Critical", 0),
                    "high_count": risk_data.get("breakdown", {}).get("High", 0),
                    "executive_summary": "Full autonomous incident analysis compiled.",
                    "analyst_notes": analyst_notes_input
                })
                db.log_audit(st.session_state.username, "GENERATE_PDF_REPORT", f"Generated incident report {report_code}")

                st.download_button(
                    label=f"⬇️ Download {report_code}.pdf",
                    data=pdf_bytes,
                    file_name=f"{report_code}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )

    with rep_col2:
        st.markdown("""
        <div style="background: rgba(17, 24, 39, 0.85); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 10px; padding: 20px;">
            <h4 style="color: #00F5FF; margin-top: 0;">📊 Multi-Format Data Exports</h4>
            <p style="color: #94A3B8; font-size: 12px;">Export raw detected telemetry for SIEM ingestion or audit compliance.</p>
        </div>
        """, unsafe_allow_html=True)

        # Excel Export
        excel_bytes = IncidentReportGenerator.generate_excel_workbook(
            st.session_state.threats,
            timeline_data,
            mitre_data.get("techniques_table", pd.DataFrame()),
            risk_data
        )
        st.download_button(
            label="📊 Download Excel Workbook (.xlsx)",
            data=excel_bytes,
            file_name="SOC_Incident_Telemetry.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True
        )

        # CSV Export
        csv_data = IncidentReportGenerator.export_csv(st.session_state.threats)
        st.download_button(
            label="📄 Download Threat Telemetry (.csv)",
            data=csv_data,
            file_name="detected_threats.csv",
            mime="text/csv",
            use_container_width=True
        )

        # JSON Export
        json_data = IncidentReportGenerator.export_json(st.session_state.threats, risk_data)
        st.download_button(
            label="🌐 Download STIX-Style Machine JSON (.json)",
            data=json_data,
            file_name="threat_telemetry.json",
            mime="application/json",
            use_container_width=True
        )

# --- PAGE 11: ADMIN & AUDIT LOGS ---
elif selected_page == "⚙️ Admin & Audit Logs":
    render_user_management()

    st.markdown("---")
    st.subheader("📜 SOC Audit Trail (Immutable)")
    st.caption("Chronological record of all user authentications, file uploads, and configuration changes.")

    audit_records = db.get_audit_logs(limit=50)
    if audit_records:
        df_audit = pd.DataFrame(audit_records)
        st.dataframe(df_audit[["timestamp", "username", "action", "details", "ip_address"]], use_container_width=True)
    else:
        st.info("Audit log is currently empty.")

    if is_admin():
        st.markdown("---")
        st.subheader("⚠️ Administrative Actions")
        if st.button("🗑️ Clear All Threat History & Uploads", type="secondary"):
            db.clear_all_threats()
            st.session_state.threats = []
            st.session_state.uploaded_files = []
            st.session_state.combined_df = pd.DataFrame()
            db.log_audit(st.session_state.username, "CLEAR_DATABASE", "Administrator purged all threats and uploads.")
            st.success("Database purged successfully.")
            st.rerun()

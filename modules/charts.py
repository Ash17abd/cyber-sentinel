"""
Interactive Visualization Module.
Provides cyber-themed Plotly charts: Risk Gauge, Severity Donut, Kill Chain Stages,
MITRE Tactical Heatmaps, Attack Velocity Timelines, and Top Threat Vectors.
"""

from typing import Dict, List, Any
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from modules.config import THEME_COLORS, SEVERITY_COLORS, KILL_CHAIN_COLORS

# Global dark theme template for Plotly charts
PLOTLY_DARK_LAYOUT = dict(
    paper_bgcolor="#111827",
    plot_bgcolor="#0B0F19",
    font=dict(family="Inter, sans-serif", color="#F8FAFC"),
    margin=dict(l=20, r=20, t=35, b=20),
    legend=dict(font=dict(color="#94A3B8"), orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
)

class SOCVisualizer:
    """Factory for enterprise SOC Plotly charts and metrics."""

    @staticmethod
    def render_kpi_cards_html(kpis: Dict[str, Any]) -> str:
        """Generates responsive HTML glowing cards for the SOC Dashboard."""
        return f"""
        <div class="kpi-container">
            <div class="kpi-card">
                <div class="kpi-label">Uploaded Telemetry</div>
                <div class="kpi-value">{kpis.get('total_files', 0)}</div>
                <div class="kpi-subtext">Active Log Feeds</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Total Threats</div>
                <div class="kpi-value" style="color: #00F5FF;">{kpis.get('total_threats', 0)}</div>
                <div class="kpi-subtext">Detected Signatures</div>
            </div>
            <div class="kpi-card critical">
                <div class="kpi-label">Critical Incidents</div>
                <div class="kpi-value" style="color: #FF0055;">{kpis.get('critical_threats', 0)}</div>
                <div class="kpi-subtext">Immediate Action</div>
            </div>
            <div class="kpi-card high">
                <div class="kpi-label">High Severity</div>
                <div class="kpi-value" style="color: #FF5E00;">{kpis.get('high_threats', 0)}</div>
                <div class="kpi-subtext">Urgent Containment</div>
            </div>
            <div class="kpi-card medium">
                <div class="kpi-label">Medium / Low</div>
                <div class="kpi-value" style="color: #FFB703;">{kpis.get('medium_threats', 0) + kpis.get('low_threats', 0)}</div>
                <div class="kpi-subtext">Active Monitoring</div>
            </div>
            <div class="kpi-card success">
                <div class="kpi-label">Malware Markers</div>
                <div class="kpi-value" style="color: #A855F7;">{kpis.get('malware_indicators', 0)}</div>
                <div class="kpi-subtext">Family Matches</div>
            </div>
            <div class="kpi-card high">
                <div class="kpi-label">Hostile / Threat IPs</div>
                <div class="kpi-value" style="color: #FB923C;">{kpis.get('suspicious_ips', 0)}</div>
                <div class="kpi-subtext">External Adversaries</div>
            </div>
            <div class="kpi-card critical">
                <div class="kpi-label">Risk Index</div>
                <div class="kpi-value" style="color: {kpis.get('risk_color', '#00FF66')};">{kpis.get('risk_score', 0)}</div>
                <div class="kpi-subtext">Tier: {kpis.get('risk_level', 'Low')}</div>
            </div>
        </div>
        """

    @staticmethod
    def create_risk_gauge(score: float, level: str) -> go.Figure:
        """Draws a semi-circular Cyber Risk Score Gauge."""
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': f"COMPOSITE RISK INDEX: {level.upper()}", 'font': {'size': 18, 'color': '#F8FAFC'}},
            number={'font': {'size': 44, 'family': 'JetBrains Mono', 'color': '#00F5FF'}, 'suffix': "/100"},
            gauge={
                'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#94A3B8"},
                'bar': {'color': "#00F5FF", 'thickness': 0.25},
                'bgcolor': "#111827",
                'borderwidth': 1,
                'bordercolor': "#374151",
                'steps': [
                    {'range': [0, 35], 'color': "rgba(0, 255, 102, 0.25)"},
                    {'range': [35, 65], 'color': "rgba(255, 183, 3, 0.25)"},
                    {'range': [65, 85], 'color': "rgba(255, 94, 0, 0.3)"},
                    {'range': [85, 100], 'color': "rgba(255, 0, 85, 0.4)"}
                ],
                'threshold': {
                    'line': {'color': "#FF0055", 'width': 4},
                    'thickness': 0.75,
                    'value': score
                }
            }
        ))
        fig.update_layout(**PLOTLY_DARK_LAYOUT, height=260)
        return fig

    @staticmethod
    def create_severity_donut(severity_counts: Dict[str, int]) -> go.Figure:
        """Draws a glowing severity breakdown donut chart."""
        labels = list(severity_counts.keys())
        values = list(severity_counts.values())
        colors = [SEVERITY_COLORS.get(label, "#38BDF8") for label in labels]

        fig = go.Figure(data=[go.Pie(
            labels=labels,
            values=values,
            hole=.55,
            marker=dict(colors=colors, line=dict(color='#0B0F19', width=2)),
            textinfo='percent+label',
            hoverinfo='label+value+percent'
        )])
        fig.update_layout(
            **PLOTLY_DARK_LAYOUT,
            title=dict(text="Threat Severity Distribution", font=dict(size=14, color="#38BDF8")),
            height=280,
            showlegend=False
        )
        return fig

    @staticmethod
    def create_kill_chain_chart(stage_counts: Dict[str, int]) -> go.Figure:
        """Draws a horizontal Kill Chain stage progression bar chart."""
        stages = list(KILL_CHAIN_COLORS.keys())
        counts = [stage_counts.get(s, 0) for s in stages]
        colors = [KILL_CHAIN_COLORS.get(s, "#00F5FF") for s in stages]

        fig = go.Figure(go.Bar(
            x=counts,
            y=stages,
            orientation='h',
            marker=dict(color=colors, line=dict(color='#0B0F19', width=1)),
            text=counts,
            textposition='auto'
        ))
        fig.update_layout(
            **PLOTLY_DARK_LAYOUT,
            title=dict(text="Cyber Kill Chain Incursion Depth", font=dict(size=14, color="#38BDF8")),
            xaxis=dict(gridcolor="#1F2937", title="Detections per Stage"),
            yaxis=dict(autorange="reversed"),
            height=300
        )
        return fig

    @staticmethod
    def create_mitre_tactic_bar(tactic_counts: Dict[str, int]) -> go.Figure:
        """Draws a bar chart showing distribution across MITRE Enterprise Tactics."""
        if not tactic_counts:
            tactic_counts = {"Initial Access": 0}
        tactics = list(tactic_counts.keys())
        counts = list(tactic_counts.values())

        fig = go.Figure(go.Bar(
            x=tactics,
            y=counts,
            marker=dict(color="#00F5FF", line=dict(color="#38BDF8", width=1.5)),
            text=counts,
            textposition='outside'
        ))
        fig.update_layout(
            **PLOTLY_DARK_LAYOUT,
            title=dict(text="MITRE ATT&CK Tactic Trigger Frequency", font=dict(size=14, color="#38BDF8")),
            xaxis=dict(tickangle=-25, gridcolor="#1F2937"),
            yaxis=dict(gridcolor="#1F2937", title="Technique Count"),
            height=300
        )
        return fig

    @staticmethod
    def create_top_threats_bar(threat_counts: Dict[str, int]) -> go.Figure:
        """Draws top detected attack signatures bar chart."""
        sorted_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        names = [x[0] for x in sorted_threats]
        counts = [x[1] for x in sorted_threats]

        fig = go.Figure(go.Bar(
            x=counts,
            y=names,
            orientation='h',
            marker=dict(color="#8A2BE2", line=dict(color="#A855F7", width=1)),
            text=counts,
            textposition='auto'
        ))
        fig.update_layout(
            **PLOTLY_DARK_LAYOUT,
            title=dict(text="Top Detected Threat Classes", font=dict(size=14, color="#38BDF8")),
            xaxis=dict(gridcolor="#1F2937", title="Occurrences"),
            yaxis=dict(autorange="reversed"),
            height=300
        )
        return fig

    @staticmethod
    def create_timeline_scatter(timeline_events: List[Dict[str, Any]]) -> go.Figure:
        """Draws an interactive chronological incident timeline."""
        if not timeline_events:
            return go.Figure()

        df = pd.DataFrame(timeline_events)
        fig = px.scatter(
            df,
            x="timestamp",
            y="phase",
            color="severity",
            hover_data=["threat_name", "source_ip", "description"],
            color_discrete_map=SEVERITY_COLORS,
            size_max=16
        )
        fig.update_traces(marker=dict(size=14, line=dict(width=2, color='#FFFFFF')))
        fig.update_layout(
            **PLOTLY_DARK_LAYOUT,
            title=dict(text="Attack Sequence Reconstruction Timeline", font=dict(size=14, color="#38BDF8")),
            xaxis=dict(gridcolor="#1F2937", title="Event Timestamp"),
            yaxis=dict(gridcolor="#1F2937", title="Intrusion Phase"),
            height=340
        )
        return fig

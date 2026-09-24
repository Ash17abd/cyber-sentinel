"""
Incident Report & Export Module.
Generates publication-quality SOC PDF Incident Reports via ReportLab,
multi-sheet Excel workbooks via OpenPyXL, and machine-readable CSV / JSON exports.
"""

import os
import io
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
import pandas as pd
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable

class IncidentReportGenerator:
    """Enterprise Incident Response Reporting & Data Exporter."""

    @staticmethod
    def generate_report_code() -> str:
        """Creates unique incident reference code."""
        now = datetime.now(timezone.utc)
        return f"INC-{now.strftime('%Y%m%d')}-{now.strftime('%H%M%S')}"

    @classmethod
    def generate_pdf_report(cls, threats: List[Dict[str, Any]],
                            risk_data: Dict[str, Any],
                            mitre_data: Dict[str, Any],
                            timeline_data: List[Dict[str, Any]],
                            analyst_name: str = "SOC Incident Responder",
                            analyst_notes: str = "") -> bytes:
        """Generates formal SOC PDF Incident Report using ReportLab."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom ReportLab Styles
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0B0F19")
        )
        h2_style = ParagraphStyle(
            'SectionH2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#0284C7"),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'BodyDark',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#1F2937")
        )
        cell_style = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#111827")
        )
        code_style = ParagraphStyle(
            'TableCellCode',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=7.5,
            leading=9,
            textColor=colors.HexColor("#B91C1C")
        )

        story = []
        report_code = cls.generate_report_code()
        gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # 1. Header Block
        story.append(Paragraph("🛡️ SOC CYBER THREAT INCIDENT REPORT", title_style))
        story.append(Paragraph(f"<b>Reference Code:</b> {report_code} | <b>Timestamp:</b> {gen_time} | <b>Lead Analyst:</b> {analyst_name}", body_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284C7"), spaceBefore=6, spaceAfter=10))

        # 2. Executive Summary & Risk Callout Box
        score = risk_data.get("score", 0.0)
        level = risk_data.get("level", "Low")
        total_threats = len(threats)
        breakdown = risk_data.get("breakdown", {})

        risk_color = colors.HexColor("#EF4444") if score >= 70 else (colors.HexColor("#F59E0B") if score >= 35 else colors.HexColor("#10B981"))
        
        exec_summary_text = (
            f"This autonomous security report synthesizes multi-source telemetry analysis. "
            f"A total of <b>{total_threats} security threats</b> were identified across the audited log feeds. "
            f"The composite organizational risk score is assessed at <b>{score}/100 ({level} Risk Tier)</b>. "
            f"Observed adversarial operations comprise {breakdown.get('Critical', 0)} Critical, {breakdown.get('High', 0)} High, "
            f"{breakdown.get('Medium', 0)} Medium, and {breakdown.get('Low', 0)} Low severity telemetry signatures."
        )

        summary_table_data = [
            [
                Paragraph(f"<b>RISK POSTURE:</b><br/><font size=18 color='{risk_color.hexval()}'><b>{score}/100</b></font><br/><b>Tier: {level.upper()}</b>", body_style),
                Paragraph(f"<b>EXECUTIVE ASSESSMENT:</b><br/>{exec_summary_text}", body_style)
            ]
        ]
        summary_table = Table(summary_table_data, colWidths=[120, 420])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F1F5F9")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#CBD5E1")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('PADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 10))

        # 3. Detected Threats Table
        story.append(Paragraph("1. Primary Threat Detections & Evidence", h2_style))
        threat_table_data = [
            [
                Paragraph("<b>Threat Vector</b>", cell_style),
                Paragraph("<b>Severity</b>", cell_style),
                Paragraph("<b>Source IP</b>", cell_style),
                Paragraph("<b>MITRE ID</b>", cell_style),
                Paragraph("<b>Kill Chain</b>", cell_style),
                Paragraph("<b>Evidence Payload Snippet</b>", cell_style)
            ]
        ]

        for t in threats[:15]:  # Top 15 threats in PDF
            sev = t.get("severity", "Medium")
            sev_color = "#DC2626" if sev == "Critical" else ("#EA580C" if sev == "High" else "#D97706")
            threat_table_data.append([
                Paragraph(f"<b>{t.get('threat_name')}</b>", cell_style),
                Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", cell_style),
                Paragraph(f"<code>{t.get('source_ip', '—')}</code>", cell_style),
                Paragraph(t.get('mitre_id', 'T1000'), cell_style),
                Paragraph(t.get('kill_chain_stage', 'Exploitation'), cell_style),
                Paragraph(str(t.get('evidence', ''))[:80], code_style)
            ])

        if len(threat_table_data) > 1:
            t_table = Table(threat_table_data, colWidths=[110, 50, 75, 55, 80, 170])
            t_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0284C7")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")]),
                ('PADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(t_table)
        else:
            story.append(Paragraph("No threats identified in session.", body_style))

        story.append(Spacer(1, 10))

        # 4. Attack Timeline Summary
        story.append(Paragraph("2. Chronological Attack Timeline Sequence", h2_style))
        timeline_rows = [
            [Paragraph("<b>Phase</b>", cell_style), Paragraph("<b>Timestamp</b>", cell_style), Paragraph("<b>Event Narrative & Impact</b>", cell_style)]
        ]
        for te in timeline_data[:8]:
            timeline_rows.append([
                Paragraph(f"<b>{te.get('phase')}</b>", cell_style),
                Paragraph(str(te.get('timestamp', ''))[:19], cell_style),
                Paragraph(f"{te.get('threat_name')}: {te.get('description', '')[:110]}", cell_style)
            ])

        tl_table = Table(timeline_rows, colWidths=[90, 110, 340])
        tl_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#334155")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(tl_table)
        story.append(Spacer(1, 10))

        # 5. MITRE ATT&CK & Recommendations
        story.append(Paragraph("3. Prioritized Containment & Remediation Roadmap", h2_style))
        recs = risk_data.get("recommendations", [])
        rec_items = []
        for r in recs:
            rec_items.append([Paragraph("•", cell_style), Paragraph(r.replace("**", ""), body_style)])

        rec_table = Table(rec_items, colWidths=[15, 525])
        rec_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('PADDING', (0,0), (-1,-1), 2)
        ]))
        story.append(rec_table)

        # 6. Analyst Notes Block
        if analyst_notes.strip():
            story.append(Spacer(1, 8))
            story.append(Paragraph("4. Lead Analyst Investigation Notes", h2_style))
            story.append(Paragraph(analyst_notes, body_style))

        # 7. Sign-off Footer Block
        story.append(Spacer(1, 16))
        sign_off_data = [
            [
                Paragraph(f"<b>Analyst Sign-off:</b> ___________________________<br/>{analyst_name} | Incident Commander", body_style),
                Paragraph(f"<b>SOC Operations Seal:</b><br/>CERTIFIED INCIDENT REPORT — VERIFIED", body_style)
            ]
        ]
        sign_table = Table(sign_off_data, colWidths=[270, 270])
        story.append(sign_table)

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()

    @classmethod
    def generate_excel_workbook(cls, threats: List[Dict[str, Any]],
                                timeline_data: List[Dict[str, Any]],
                                mitre_df: pd.DataFrame,
                                risk_data: Dict[str, Any]) -> bytes:
        """Generates comprehensive multi-tab Excel incident workbook."""
        buffer = io.BytesIO()
        wb = openpyxl.Workbook()

        header_fill = PatternFill(start_color="0284C7", end_color="0284C7", fill_type="solid")
        header_font = Font(name="Arial", size=11, bold=True, color="FFFFFF")
        border = Border(
            left=Side(style='thin', color="E2E8F0"),
            right=Side(style='thin', color="E2E8F0"),
            top=Side(style='thin', color="E2E8F0"),
            bottom=Side(style='thin', color="E2E8F0")
        )

        # Tab 1: Executive Overview
        ws1 = wb.active
        ws1.title = "Incident_Overview"
        ws1.append(["SOC CYBER INCIDENT INVESTIGATION REPORT"])
        ws1.append(["Generated At", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")])
        ws1.append(["Composite Risk Score", risk_data.get("score", 0.0)])
        ws1.append(["Risk Tier", risk_data.get("level", "Low")])
        ws1.append(["Total Detected Threats", len(threats)])
        ws1["A1"].font = Font(size=14, bold=True, color="0284C7")

        # Tab 2: Detected Threats
        ws2 = wb.create_sheet(title="Detected_Threats")
        headers = ["Threat Name", "Severity", "Confidence", "Source IP", "Destination IP", "Timestamp", "MITRE ID", "Kill Chain Stage", "Evidence"]
        ws2.append(headers)
        for cell in ws2[1]:
            cell.fill = header_fill
            cell.font = header_font

        for t in threats:
            ws2.append([
                t.get("threat_name"),
                t.get("severity"),
                t.get("confidence"),
                t.get("source_ip"),
                t.get("destination_ip"),
                t.get("timestamp"),
                t.get("mitre_id"),
                t.get("kill_chain_stage"),
                t.get("evidence")
            ])

        # Tab 3: Attack Timeline
        ws3 = wb.create_sheet(title="Attack_Timeline")
        ws3.append(["Phase", "Timestamp", "Threat Name", "Source IP", "Severity", "Description"])
        for cell in ws3[1]:
            cell.fill = header_fill
            cell.font = header_font

        for tl in timeline_data:
            ws3.append([
                tl.get("phase"),
                tl.get("timestamp"),
                tl.get("threat_name"),
                tl.get("source_ip"),
                tl.get("severity"),
                tl.get("description")
            ])

        # Tab 4: MITRE ATT&CK Matrix
        if not mitre_df.empty:
            ws4 = wb.create_sheet(title="MITRE_ATTACK_Matrix")
            ws4.append(list(mitre_df.columns))
            for cell in ws4[1]:
                cell.fill = header_fill
                cell.font = header_font
            for _, r in mitre_df.iterrows():
                ws4.append(list(r.values))

        wb.save(buffer)
        buffer.seek(0)
        return buffer.getvalue()

    @staticmethod
    def export_csv(threats: List[Dict[str, Any]]) -> str:
        """Exports detected threats as CSV string."""
        if not threats:
            return "threat_name,severity,confidence,source_ip,destination_ip,timestamp,mitre_id,kill_chain_stage,evidence\n"
        df = pd.DataFrame(threats)
        return df.to_csv(index=False)

    @staticmethod
    def export_json(threats: List[Dict[str, Any]], risk_data: Dict[str, Any]) -> str:
        """Exports entire incident state as indented JSON."""
        payload = {
            "incident_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "report_standard": "STIX-compatible JSON Telemetry",
                "risk_score": risk_data.get("score", 0.0),
                "risk_level": risk_data.get("level", "Low")
            },
            "threats_count": len(threats),
            "threats": threats,
            "triage_recommendations": risk_data.get("recommendations", [])
        }
        return json.dumps(payload, indent=2)

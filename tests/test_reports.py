"""Unit tests for Report Generation (PDF, Excel, CSV, JSON)."""

import unittest
import pandas as pd
from modules.report_generator import IncidentReportGenerator

class TestReports(unittest.TestCase):

    def setUp(self):
        self.sample_threats = [{
            "threat_name": "SQL Injection",
            "severity": "Critical",
            "confidence": 95.0,
            "source_ip": "198.51.100.45",
            "destination_ip": "10.0.0.1",
            "timestamp": "2026-09-19T12:00:00",
            "evidence": "UNION SELECT null, username, password FROM users",
            "mitre_id": "T1190",
            "kill_chain_stage": "Exploitation"
        }]
        self.sample_risk = {
            "score": 85.5,
            "level": "Critical",
            "breakdown": {"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
            "recommendations": ["Block IP 198.51.100.45 on WAF"]
        }
        self.sample_mitre = {"techniques_table": pd.DataFrame()}
        self.sample_timeline = [{
            "phase": "Initial Access",
            "timestamp": "2026-09-19T12:00:00",
            "threat_name": "SQL Injection",
            "source_ip": "198.51.100.45",
            "severity": "Critical",
            "description": "SQL Injection payload observed"
        }]

    def test_pdf_generation(self):
        pdf_bytes = IncidentReportGenerator.generate_pdf_report(
            self.sample_threats,
            self.sample_risk,
            self.sample_mitre,
            self.sample_timeline,
            analyst_name="SOC Lead"
        )
        self.assertGreater(len(pdf_bytes), 500)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

    def test_excel_generation(self):
        excel_bytes = IncidentReportGenerator.generate_excel_workbook(
            self.sample_threats,
            self.sample_timeline,
            pd.DataFrame(),
            self.sample_risk
        )
        self.assertGreater(len(excel_bytes), 500)

    def test_csv_export(self):
        csv_str = IncidentReportGenerator.export_csv(self.sample_threats)
        self.assertIn("SQL Injection", csv_str)
        self.assertIn("198.51.100.45", csv_str)

    def test_json_export(self):
        json_str = IncidentReportGenerator.export_json(self.sample_threats, self.sample_risk)
        self.assertIn("SQL Injection", json_str)
        self.assertIn("85.5", json_str)

if __name__ == "__main__":
    unittest.main()

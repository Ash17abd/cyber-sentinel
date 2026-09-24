"""Unit tests for Threat Detection Engine."""

import unittest
import pandas as pd
from modules.threat_detection import ThreatDetectionEngine

class TestThreatDetection(unittest.TestCase):

    def test_sql_injection_detection(self):
        df = pd.DataFrame([{
            "timestamp": "2026-09-19T10:00:00",
            "source_ip": "192.168.1.55",
            "destination_ip": "10.0.0.1",
            "event_type": "HTTP_GET",
            "raw_log": "GET /login?user=admin' UNION SELECT password FROM users--",
            "details": "GET /login?user=admin' UNION SELECT password FROM users--",
            "url": "/login?user=admin' UNION SELECT password FROM users--",
            "status_code": "200"
        }])
        threats = ThreatDetectionEngine.analyze_events(df)
        self.assertTrue(any(t["threat_name"] == "SQL Injection" for t in threats))

    def test_xss_detection(self):
        df = pd.DataFrame([{
            "timestamp": "2026-09-19T10:05:00",
            "source_ip": "192.168.1.66",
            "destination_ip": "10.0.0.1",
            "event_type": "HTTP_POST",
            "raw_log": "<script>alert(document.cookie);</script>",
            "details": "<script>alert(document.cookie);</script>",
            "url": "/submit",
            "status_code": "200"
        }])
        threats = ThreatDetectionEngine.analyze_events(df)
        self.assertTrue(any(t["threat_name"] == "Cross Site Scripting (XSS)" for t in threats))

    def test_brute_force_detection(self):
        rows = []
        for i in range(7):
            rows.append({
                "timestamp": f"2026-09-19T10:10:0{i}",
                "source_ip": "185.220.101.5",
                "destination_ip": "10.0.0.1",
                "event_type": "HTTP_POST",
                "raw_log": "Failed authentication attempt",
                "details": "Failed password login for user admin",
                "url": "/auth",
                "status_code": "401"
            })
        df = pd.DataFrame(rows)
        threats = ThreatDetectionEngine.analyze_events(df)
        self.assertTrue(any(t["threat_name"] == "Brute Force Attack" for t in threats))

    def test_ransomware_detection(self):
        df = pd.DataFrame([{
            "timestamp": "2026-09-19T10:15:00",
            "source_ip": "10.0.0.15",
            "destination_ip": "10.0.0.15",
            "event_type": "WinEvent_1",
            "raw_log": "vssadmin delete shadows /all /quiet",
            "details": "Process Creation: vssadmin delete shadows /all /quiet",
            "url": "",
            "status_code": "1"
        }])
        threats = ThreatDetectionEngine.analyze_events(df)
        self.assertTrue(any(t["threat_name"] == "Ransomware Indicators" for t in threats))

if __name__ == "__main__":
    unittest.main()

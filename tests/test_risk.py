"""Unit tests for Risk Engine."""

import unittest
from modules.risk_engine import RiskScoreEngine

class TestRiskEngine(unittest.TestCase):

    def test_empty_risk_score(self):
        result = RiskScoreEngine.calculate_risk_score([])
        self.assertEqual(result["score"], 0.0)
        self.assertEqual(result["level"], "Low")

    def test_critical_risk_score(self):
        threats = [
            {"threat_name": "Ransomware Indicators", "severity": "Critical"},
            {"threat_name": "Command Injection", "severity": "Critical"},
            {"threat_name": "Malicious IP Addresses", "severity": "Critical", "source_ip": "198.51.100.45"},
            {"threat_name": "Credential Theft", "severity": "Critical"}
        ]
        malware = [{"family": "Ransomware", "likelihood_value": 85}]
        result = RiskScoreEngine.calculate_risk_score(threats, malware, failed_logins=10)
        self.assertGreaterEqual(result["score"], 70.0)
        self.assertIn(result["level"], ["High", "Critical"])
        self.assertGreater(len(result["recommendations"]), 0)

if __name__ == "__main__":
    unittest.main()

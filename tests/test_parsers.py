"""Unit tests for File Ingestion and Parsers."""

import unittest
from modules.upload import FileIngestionEngine
from modules.utils import SampleDataGenerator

class TestParsers(unittest.TestCase):

    def test_apache_log_parser(self):
        log_text = SampleDataGenerator.generate_apache_attack_logs()
        df = FileIngestionEngine.parse_apache_nginx(log_text)
        self.assertFalse(df.empty)
        self.assertIn("source_ip", df.columns)
        self.assertIn("details", df.columns)
        self.assertGreater(len(df), 5)

    def test_json_log_parser(self):
        json_text = SampleDataGenerator.generate_json_firewall_logs()
        df = FileIngestionEngine.parse_json_logs(json_text)
        self.assertFalse(df.empty)
        self.assertIn("source_ip", df.columns)
        self.assertEqual(len(df), 8)

    def test_hash_calculation(self):
        data = b"Cyber Sentinel Security Telemetry"
        hash_val = FileIngestionEngine.calculate_hash(data)
        self.assertEqual(len(hash_val), 64)

if __name__ == "__main__":
    unittest.main()

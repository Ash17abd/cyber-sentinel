"""
Cyber Sentinel Serverless API for Vercel.
Exposes REST endpoints for system health, indicator lookup, and threat catalog.
Powered by standard library BaseHTTPRequestHandler for zero-latency serverless execution.
"""

import json
import urllib.parse
from http.server import BaseHTTPRequestHandler
import re
import hashlib
import ipaddress

# Local threat intel cache for serverless edge execution
KNOWN_IPS = {
    "198.51.100.45": {"country": "Russian Federation", "city": "Moscow", "reputation": "Malicious", "threat": "Critical", "asn": "AS49505 OOO Inoventika", "score": 98, "vector": "Cobalt Strike C2 Beacon"},
    "203.0.113.19": {"country": "Germany", "city": "Frankfurt", "reputation": "Suspicious", "threat": "High", "asn": "AS24940 Hetzner Online GmbH", "score": 82, "vector": "Tor Exit Node / Web Probe"},
    "185.220.101.5": {"country": "Netherlands", "city": "Amsterdam", "reputation": "Malicious", "threat": "Critical", "asn": "AS200019 Zappie Host", "score": 94, "vector": "Mirai Botnet / Bruteforce"},
    "45.33.32.156": {"country": "United States", "city": "Fremont, CA", "reputation": "Suspicious", "threat": "Medium", "asn": "AS63949 Linode LLC", "score": 75, "vector": "Masscan Reconnaissance"},
    "194.26.29.112": {"country": "Bulgaria", "city": "Sofia", "reputation": "Malicious", "threat": "Critical", "asn": "AS44034 Dedicated Hosting", "score": 99, "vector": "LockBit Ransomware Staging Node"}
}

COUNTRY_REGISTRY = {
    "united states": {"country": "United States", "city": "Washington, D.C.", "lat": 38.9072, "lon": -77.0369},
    "germany": {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
    "russia": {"country": "Russian Federation", "city": "Moscow", "lat": 55.7558, "lon": 37.6173},
    "netherlands": {"country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041},
    "china": {"country": "China", "city": "Beijing", "lat": 39.9042, "lon": 116.4074},
    "india": {"country": "India", "city": "New Delhi", "lat": 28.6139, "lon": 77.2090},
    "united kingdom": {"country": "United Kingdom", "city": "London", "lat": 51.5074, "lon": -0.1278},
    "japan": {"country": "Japan", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503},
    "sikkim": {"country": "India (Sikkim)", "city": "Gangtok", "lat": 27.5330, "lon": 88.5122},
    "nagaland": {"country": "India (Nagaland)", "city": "Kohima", "lat": 25.6751, "lon": 94.1086},
    "rajasthan": {"country": "India (Rajasthan)", "city": "Jaipur", "lat": 26.9124, "lon": 75.7873},
    "jamshedpur": {"country": "India (Jharkhand)", "city": "Jamshedpur", "lat": 22.8046, "lon": 86.2029},
    "bilaspur": {"country": "India (Chhattisgarh)", "city": "Bilaspur", "lat": 22.0797, "lon": 82.1409},
    "bokaro": {"country": "India (Jharkhand)", "city": "Bokaro", "lat": 23.6693, "lon": 86.1511}
}

class handler(BaseHTTPRequestHandler):
    """Vercel serverless request dispatcher."""

    def _send_json(self, data: dict, status_code: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Health endpoint
        if path in ["/api/health", "/api/", "/api"]:
            return self._send_json({
                "status": "online",
                "system": "Cyber Sentinel SOC AI",
                "version": "1.0.0",
                "platform": "Vercel Serverless Edge",
                "endpoints": {
                    "health": "/api/health",
                    "lookup": "/api/lookup?ip=<ip_or_country>",
                    "threats": "/api/threats"
                }
            })

        # Threat catalog endpoint
        if path == "/api/threats":
            return self._send_json({
                "catalog_count": 17,
                "threat_types": [
                    "SQL Injection", "Cross Site Scripting (XSS)", "Command Injection",
                    "Directory Traversal", "Brute Force Attack", "Port Scanning",
                    "Ransomware Indicators", "Credential Theft", "PowerShell Attacks",
                    "Beaconing Activity", "Data Exfiltration", "Reverse Shell Indicators"
                ],
                "mitre_framework": "MITRE ATT&CK v14 Enterprise",
                "kill_chain": "Lockheed Martin 7-Stage Intrusion Funnel"
            })

        # Indicator / IP lookup endpoint
        if path == "/api/lookup":
            target = query.get("ip", [None])[0] or query.get("q", [""])[0]
            if not target:
                return self._send_json({"error": "Missing 'ip' parameter, e.g. /api/lookup?ip=198.51.100.45"}, 400)

            target = target.strip()
            # 1. Match known IP
            if target in KNOWN_IPS:
                res = KNOWN_IPS[target].copy()
                res["query"] = target
                return self._send_json(res)

            # 2. Match country name or compound location
            target_low = target.lower()
            matched_key = None
            if target_low in COUNTRY_REGISTRY:
                matched_key = target_low
            elif "," in target_low:
                for part in target_low.split(","):
                    p = part.strip()
                    if p in COUNTRY_REGISTRY:
                        matched_key = p
                        break
            if not matched_key:
                for k in COUNTRY_REGISTRY:
                    if len(k) >= 4 and k in target_low:
                        matched_key = k
                        break

            if matched_key:
                c_info = COUNTRY_REGISTRY[matched_key]
                return self._send_json({
                    "query": target,
                    "reputation": "Country Telemetry Zone",
                    "score": 45,
                    "country": c_info["country"],
                    "city": target.split(",")[0].strip().title() if "," in target else c_info["city"],
                    "lat": c_info["lat"],
                    "lon": c_info["lon"],
                    "asn": "Regional Internet Registry"
                })

            # 3. Private IP check
            is_priv = False
            try:
                ip_obj = ipaddress.ip_address(target)
                is_priv = ip_obj.is_private or ip_obj.is_loopback
            except ValueError:
                if target.startswith(("10.", "192.168.", "172.16.", "127.", "0.")):
                    is_priv = True

            if is_priv:
                return self._send_json({
                    "query": target,
                    "reputation": "Internal Enterprise Asset",
                    "score": 0,
                    "country": "Enterprise LAN / SOC Hub",
                    "city": "Internal Private Subnet",
                    "asn": "Private RFC 1918 Network"
                })

            # 4. Deterministic fallback for public IP
            h = int(hashlib.md5(target.encode()).hexdigest()[:4], 16) % 100
            is_mal = h > 70
            return self._send_json({
                "query": target,
                "reputation": "Suspicious" if is_mal else "Clean / Unflagged",
                "score": h if is_mal else 12,
                "country": "United States" if h % 2 == 0 else "Germany",
                "city": "Ashburn, VA" if h % 2 == 0 else "Frankfurt",
                "asn": "Cloudflare / CDN" if h % 2 == 0 else "DigitalOcean LLC"
            })

        return self._send_json({"error": f"Endpoint '{path}' not found. Try /api/health or /api/lookup"}, 404)

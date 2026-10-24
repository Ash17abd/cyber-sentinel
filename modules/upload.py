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
        col_clean_map = {re.sub(r'[\s_\-]+', '', str(col).lower()): col for col in df.columns}

        time_keys = ['timecreated', 'time', 'timestamp', 'date', 'datetime', 'utctime']
        time_col = next((col_clean_map[k] for k in time_keys if k in col_clean_map), None)

        event_keys = ['eventid', 'id', 'recordid']
        event_col = next((col_clean_map[k] for k in event_keys if k in col_clean_map), None)

        ip_keys = ['ipaddress', 'sourceip', 'srcip', 'attackerip', 'clientip', 'remoteip', 'host', 'ip', 'sourceaddress', 'srcaddr']
        ip_col = next((col_clean_map[k] for k in ip_keys if k in col_clean_map), None)

        dst_ip_keys = ['destinationip', 'dstip', 'targetip', 'serverip', 'destip', 'destinationaddress', 'dstaddr']
        dst_ip_col = next((col_clean_map[k] for k in dst_ip_keys if k in col_clean_map), None)

        msg_keys = ['message', 'details', 'commandline', 'processname', 'description', 'rawlog', 'eventdata']
        msg_col = next((col_clean_map[k] for k in msg_keys if k in col_clean_map), None)

        # Location keys if exported with enrichment
        country_keys = ['country', 'countryname', 'countrycode', 'location', 'geo']
        country_col = next((col_clean_map[k] for k in country_keys if k in col_clean_map), None)

        for _, row in df.iterrows():
            ts = str(row[time_col]) if time_col and pd.notna(row[time_col]) else datetime.now(timezone.utc).isoformat()
            eid = str(row[event_col]) if event_col and pd.notna(row[event_col]) else "EVENT"
            sip = str(row[ip_col]) if ip_col and pd.notna(row[ip_col]) else "127.0.0.1"
            dip = str(row[dst_ip_col]) if dst_ip_col and pd.notna(row[dst_ip_col]) else "10.0.0.1"
            country_val = str(row[country_col]) if country_col and pd.notna(row[country_col]) else ""
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
                "user_agent": "",
                "country": country_val
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
                parsed_items = data.get("logs") or data.get("events") or data.get("records") or [data]
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
        """Maps any generic DataFrame to the standard SOC event schema with location retention."""
        normalized = []
        # Normalized alphanumeric column names without spaces, underscores, or hyphens
        clean_col_map = {re.sub(r'[\s_\-]+', '', str(c).lower()): c for c in df.columns}

        time_keys = ['timestamp', 'time', 'date', 'datetime', 'timecreated', 'utctime', 'eventtime']
        time_key = next((clean_col_map[k] for k in time_keys if k in clean_col_map), None)

        src_keys = [
            'sourceip', 'srcip', 'attackerip', 'clientip', 'originip', 'remoteip',
            'hostip', 'sourceaddress', 'srcaddr', 'source', 'src', 'host', 'ipaddress', 'ip',
            'origin', 'senderip', 'clientaddress'
        ]
        src_key = next((clean_col_map[k] for k in src_keys if k in clean_col_map), None)

        # Fallback: scan columns for IPv4 pattern if no column named source IP
        if not src_key:
            ipv4_pat = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
            for col in df.columns:
                series = df[col].dropna().astype(str)
                if not series.empty and series.iloc[:5].apply(lambda x: bool(ipv4_pat.match(x.strip()))).any():
                    src_key = col
                    break

        dst_keys = [
            'destinationip', 'dstip', 'targetip', 'serverip', 'destip',
            'destinationaddress', 'dstaddr', 'destination', 'dst', 'target', 'destaddress'
        ]
        dst_key = next((clean_col_map[k] for k in dst_keys if k in clean_col_map), None)

        evt_keys = ['eventtype', 'action', 'event', 'attacktype', 'signature', 'method', 'activity', 'category']
        evt_key = next((clean_col_map[k] for k in evt_keys if k in clean_col_map), None)

        msg_keys = ['message', 'details', 'query', 'payload', 'url', 'command', 'raw', 'rawlog', 'description', 'info']
        msg_key = next((clean_col_map[k] for k in msg_keys if k in clean_col_map), None)

        # Geographic Location Columns (preserve if present in dataset)
        country_keys = [
            'geolocationdata', 'geolocation', 'geodata', 'geoloc', 'locationdata', 'geoinfo',
            'sourcecountry', 'srccountry', 'attackerlocation', 'origincountry', 'country',
            'countryname', 'countrycode', 'location', 'geo', 'geocountry', 'sourcegeolocation'
        ]
        country_key = next((clean_col_map[k] for k in country_keys if k in clean_col_map), None)

        city_keys = ['city', 'cityname', 'sourcecity', 'srccity', 'town', 'state', 'region', 'province']
        city_key = next((clean_col_map[k] for k in city_keys if k in clean_col_map), None)

        lat_keys = ['latitude', 'lat', 'srclat', 'sourcelatitude', 'originlatitude']
        lat_key = next((clean_col_map[k] for k in lat_keys if k in clean_col_map), None)

        lon_keys = ['longitude', 'lon', 'lng', 'srclon', 'sourcelongitude', 'originlongitude']
        lon_key = next((clean_col_map[k] for k in lon_keys if k in clean_col_map), None)

        isp_keys = ['isp', 'asn', 'org', 'organization', 'provider', 'asname', 'carrier', 'networksegment']
        isp_key = next((clean_col_map[k] for k in isp_keys if k in clean_col_map), None)

        sev_keys = ['severitylevel', 'severity', 'threatlevel', 'priority', 'level']
        sev_key = next((clean_col_map[k] for k in sev_keys if k in clean_col_map), None)

        from modules.attack_map import AttackMapEngine

        for _, row in df.iterrows():
            ts = str(row[time_key]) if time_key and pd.notna(row[time_key]) else datetime.now(timezone.utc).isoformat()
            raw = " ".join([f"{k}:{v}" for k, v in row.items() if pd.notna(v)])
            details = str(row[msg_key]) if msg_key and pd.notna(row[msg_key]) else raw

            # Find source IP, or inspect raw string if still default
            if src_key and pd.notna(row[src_key]) and str(row[src_key]).strip():
                src = str(row[src_key]).strip()
            else:
                found_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
                src = found_ips[0] if found_ips else "192.168.1.100"

            if dst_key and pd.notna(row[dst_key]) and str(row[dst_key]).strip():
                dst = str(row[dst_key]).strip()
            else:
                found_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
                dst = found_ips[1] if len(found_ips) > 1 else "10.0.0.1"

            evt = str(row[evt_key]) if evt_key and pd.notna(row[evt_key]) else "GENERIC_EVENT"
            c_raw = str(row[country_key]).strip() if country_key and pd.notna(row[country_key]) else ""
            city_raw = str(row[city_key]).strip() if city_key and pd.notna(row[city_key]) else ""
            lat_val = float(row[lat_key]) if lat_key and pd.notna(row[lat_key]) and str(row[lat_key]).replace('.', '', 1).replace('-', '', 1).isdigit() else 0.0
            lon_val = float(row[lon_key]) if lon_key and pd.notna(row[lon_key]) and str(row[lon_key]).replace('.', '', 1).replace('-', '', 1).isdigit() else 0.0
            isp_val = str(row[isp_key]).strip() if isp_key and pd.notna(row[isp_key]) else ""
            sev_val = str(row[sev_key]).strip().capitalize() if sev_key and pd.notna(row[sev_key]) else "Medium"

            # Parse compound location strings (e.g. Kaggle "Jamshedpur, Sikkim", "Bokaro, Rajasthan")
            if c_raw and "," in c_raw:
                parts = [p.strip() for p in c_raw.split(",") if p.strip()]
                if len(parts) >= 2:
                    city_val = parts[0]
                    c_val = parts[1]
                    loc_val = f"{city_val}, {c_val}"
                else:
                    city_val = city_raw or c_raw
                    c_val = c_raw
                    loc_val = c_raw
            else:
                c_val = c_raw
                city_val = city_raw
                loc_val = f"{city_val}, {c_val}".strip(", ") if (city_val and c_val) else (c_val or city_val)

            # Auto-resolve coordinates if not explicitly in numeric columns
            if lat_val == 0.0 or lon_val == 0.0:
                loc_res = AttackMapEngine.resolve_location_name(loc_val or c_val)
                if loc_res:
                    lat_val = loc_res["lat"]
                    lon_val = loc_res["lon"]
                    if not c_val:
                        c_val = loc_res["country"]
                    if not city_val:
                        city_val = loc_res["city"]
                    if not isp_val:
                        isp_val = loc_res.get("isp", "")
                elif src and src not in ["0.0.0.0", "127.0.0.1", "192.168.1.100"]:
                    ip_geo = AttackMapEngine.resolve_ip(src, fallback_country=c_val)
                    lat_val = ip_geo.get("lat", 0.0)
                    lon_val = ip_geo.get("lon", 0.0)
                    if not c_val:
                        c_val = ip_geo.get("country", "")
                    if not city_val:
                        city_val = ip_geo.get("city", "")
                    if not isp_val:
                        isp_val = ip_geo.get("isp", "")

            entry = {
                "timestamp": ts,
                "source_ip": src,
                "destination_ip": dst,
                "event_type": evt,
                "raw_log": raw,
                "details": details,
                "url": str(row.get('url', '')) if 'url' in row and pd.notna(row['url']) else "",
                "status_code": str(row.get('status', '200')) if 'status' in row and pd.notna(row['status']) else "",
                "user_agent": str(row.get('user_agent', '')) if 'user_agent' in row and pd.notna(row['user_agent']) else "",
                "country": c_val or "Detected Origin",
                "city": city_val or "Regional Point",
                "location": loc_val or (f"{city_val}, {c_val}" if city_val and c_val else c_val),
                "latitude": lat_val,
                "longitude": lon_val,
                "isp": isp_val,
                "severity": sev_val
            }
            normalized.append(entry)
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
                # Extract any real IP from the line
                ip_match = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                sip = ip_match[0] if ip_match else "PDF_REPORT_SOURCE"
                dip = ip_match[1] if len(ip_match) > 1 else "INTERNAL"

                records.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": sip,
                    "destination_ip": dip,
                    "event_type": "REPORT_STATEMENT",
                    "raw_log": line,
                    "details": line,
                    "url": "",
                    "status_code": "PDF",
                    "user_agent": "",
                    "country": ""
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
                            ip_candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                            sip = ip_candidates[0] if ip_candidates else "127.0.0.1"
                            dip = ip_candidates[1] if len(ip_candidates) > 1 else "10.0.0.1"
                            rows.append({
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "source_ip": sip,
                                "destination_ip": dip,
                                "event_type": "SYSLOG_LINE",
                                "raw_log": line,
                                "details": line,
                                "url": "",
                                "status_code": "0",
                                "user_agent": "",
                                "country": ""
                            })
                    df_events = pd.DataFrame(rows)

            else:
                # Unsupported or unknown extension, attempt fallback as text
                detected_type = f"Unknown ({ext})"
                text_content = file_bytes.decode(encoding, errors='replace')
                raw_text = text_content[:2000]
                rows = []
                for l in text_content.splitlines():
                    if l.strip():
                        ip_candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", l)
                        sip = ip_candidates[0] if ip_candidates else "0.0.0.0"
                        dip = ip_candidates[1] if len(ip_candidates) > 1 else "0.0.0.0"
                        rows.append({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "source_ip": sip,
                            "destination_ip": dip,
                            "event_type": "RAW_TEXT",
                            "raw_log": l,
                            "details": l,
                            "url": "",
                            "status_code": "0",
                            "user_agent": "",
                            "country": ""
                        })
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

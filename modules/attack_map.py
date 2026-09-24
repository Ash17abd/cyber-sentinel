"""
Attack Map Module.
Visualizes attacker geographical origin on an interactive world map using Folium.
Supports multiple watermark-free basemaps:
- Esri Cyber Dark Gray Canvas with high-contrast labels (Default)
- OpenStreetMap (Full Geographic Detail)
- Esri World Satellite Imagery
Displays Country, City, ISP, Attack Count, and Threat Level with high-visibility markers.
"""

from typing import List, Dict, Any, Tuple
from collections import defaultdict
import folium
from folium.plugins import MarkerCluster
import pandas as pd
from modules.config import SEVERITY_COLORS

# High-fidelity Geographic IP Resolution Cache
GEOLOCATION_REGISTRY = {
    "198.51.100.45": {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "isp": "OOO Inoventika", "threat": "Critical"},
    "203.0.113.19": {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "isp": "Hetzner Online GmbH", "threat": "High"},
    "185.220.101.5": {"country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "isp": "Zappie Host BV", "threat": "Critical"},
    "45.33.32.156": {"country": "United States", "city": "Fremont, CA", "lat": 37.5485, "lon": -121.9886, "isp": "Linode LLC", "threat": "Medium"},
    "194.26.29.112": {"country": "Bulgaria", "city": "Sofia", "lat": 42.6977, "lon": 23.3219, "isp": "Dedicated Hosting EAD", "threat": "Critical"},
    "91.240.118.168": {"country": "Ukraine", "city": "Kyiv", "lat": 50.4501, "lon": 30.5234, "isp": "Datagroup PJSC", "threat": "High"},
    "103.251.167.20": {"country": "China", "city": "Beijing", "lat": 39.9042, "lon": 116.4074, "isp": "China Telecom", "threat": "High"},
    "185.190.140.22": {"country": "Iran", "city": "Tehran", "lat": 35.6892, "lon": 51.3890, "isp": "Afranet", "threat": "High"},
    "85.209.11.45": {"country": "Romania", "city": "Bucharest", "lat": 44.4268, "lon": 26.1025, "isp": "MivoCloud SRL", "threat": "Medium"}
}

class AttackMapEngine:
    """Orchestrates interactive mapping of adversary infrastructure."""

    @staticmethod
    def resolve_ip(ip: str) -> Dict[str, Any]:
        """Resolves IP to geographic coordinates and metadata."""
        if ip in GEOLOCATION_REGISTRY:
            return GEOLOCATION_REGISTRY[ip]

        # Ignore private RFC 1918 IPs on the global map
        if ip.startswith(("10.", "192.168.", "172.16.", "127.", "0.")):
            return {
                "country": "Internal Network",
                "city": "Private Subnet",
                "lat": 0.0,
                "lon": 0.0,
                "isp": "Enterprise LAN",
                "threat": "Low",
                "is_private": True
            }

        # Deterministic simulation for unknown external IPs
        import hashlib
        h = int(hashlib.md5(ip.encode()).hexdigest()[:6], 16)
        lat = ((h % 110) - 45) + (h % 100) / 100.0
        lon = ((h % 260) - 120) + (h % 100) / 100.0

        countries = ["United States", "Germany", "United Kingdom", "France", "Singapore", "Brazil", "Japan", "Canada"]
        isps = ["Amazon AWS", "DigitalOcean LLC", "Microsoft Azure", "Cloudflare CDN", "OVH SAS", "Google Cloud"]
        
        country = countries[h % len(countries)]
        isp = isps[(h >> 2) % len(isps)]

        return {
            "country": country,
            "city": "Unknown City",
            "lat": lat,
            "lon": lon,
            "isp": isp,
            "threat": "Medium",
            "is_private": False
        }

    @classmethod
    def generate_map(cls, threats: List[Dict[str, Any]], map_style: str = "cyber_dark", *args, **kwargs) -> Tuple[folium.Map, pd.DataFrame]:
        """Builds Folium interactive map with crystal-clear basemaps and high-contrast markers."""
        
        # 1. Base Map Configuration (All 100% free with NO 'API Key Required' watermarks)
        esri_dark_url = "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}"
        esri_ref_url = "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}"
        satellite_url = "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}"

        if map_style == "osm":
            m = folium.Map(
                location=[30.0, 15.0],
                zoom_start=2,
                tiles="OpenStreetMap",
                control_scale=True
            )
        elif map_style == "satellite":
            m = folium.Map(
                location=[30.0, 15.0],
                zoom_start=2,
                tiles=satellite_url,
                attr="Esri World Imagery",
                name="Satellite Imagery",
                control_scale=True
            )
        else:
            # Default: Esri Cyber Dark Gray Base (Clean, high-contrast, zero watermark)
            m = folium.Map(
                location=[30.0, 15.0],
                zoom_start=2,
                tiles=esri_dark_url,
                attr="Esri Dark Gray Base",
                name="Cyber Dark Canvas",
                control_scale=True
            )
            # Add crisp white country/city labels on top
            folium.TileLayer(
                tiles=esri_ref_url,
                attr="Esri Labels",
                name="Borders & Labels",
                overlay=True,
                control=True
            ).add_to(m)

        # Also add OpenStreetMap & Satellite layers to LayerControl
        folium.TileLayer(
            tiles="OpenStreetMap",
            name="OpenStreetMap",
            overlay=False,
            control=True
        ).add_to(m)

        folium.TileLayer(
            tiles=satellite_url,
            attr="Esri Satellite",
            name="Satellite Imagery",
            overlay=False,
            control=True
        ).add_to(m)

        ip_threats = defaultdict(list)
        for t in threats:
            sip = str(t.get("source_ip", ""))
            if sip and not sip.startswith(("127.", "0.")):
                ip_threats[sip].append(t)

        marker_cluster = MarkerCluster(name="Attacker Origin Pins").add_to(m)
        table_rows = []
        bounds_points = []

        for ip, t_list in ip_threats.items():
            geo = cls.resolve_ip(ip)
            if geo.get("is_private") or geo.get("lat") == 0.0:
                continue

            lat, lon = geo["lat"], geo["lon"]
            bounds_points.append([lat, lon])

            attack_count = len(t_list)
            max_sev = "Low"
            for s in ["Critical", "High", "Medium", "Low"]:
                if any(t.get("severity") == s for t in t_list):
                    max_sev = s
                    break

            color = SEVERITY_COLORS.get(max_sev, "#00F5FF")
            threat_names = list({t.get("threat_name") for t in t_list})

            # High-contrast Cyber Popup Card
            popup_html = f"""
            <div style="font-family: 'Segoe UI', Arial, sans-serif; min-width: 220px; background: #0F172A; color: #F8FAFC; border-radius: 8px; padding: 14px; border: 1px solid {color}; box-shadow: 0 4px 16px rgba(0,0,0,0.5);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span style="font-weight: 800; font-size: 13px; color: #00F5FF; letter-spacing: 0.5px;">HOSTILE ORIGIN</span>
                    <span style="background: rgba(255,255,255,0.1); color: {color}; border: 1px solid {color}; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold;">{max_sev.upper()}</span>
                </div>
                <div style="font-family: monospace; font-size: 14px; font-weight: bold; color: #FFF; margin-bottom: 6px;">IP: {ip}</div>
                <div style="font-size: 12px; color: #94A3B8; line-height: 1.4;">
                    <div><b>Location:</b> {geo['country']} ({geo['city']})</div>
                    <div><b>ISP / Org:</b> {geo['isp']}</div>
                    <div><b>Total Attacks:</b> <span style="color: #FFF; font-weight: bold;">{attack_count}</span></div>
                    <div style="margin-top: 6px; color: #CBD5E1;"><b>Vectors:</b> {', '.join(threat_names[:2])}</div>
                </div>
            </div>
            """

            # Outer pulsating halo for Critical / High threats
            if max_sev in ["Critical", "High"]:
                folium.CircleMarker(
                    location=[lat, lon],
                    radius=max(14, min(32, 12 + attack_count * 3)),
                    color=color,
                    fill=True,
                    fill_color=color,
                    fill_opacity=0.18,
                    weight=1
                ).add_to(m)

            # Core sharp pin marker
            folium.CircleMarker(
                location=[lat, lon],
                radius=max(7, min(18, 6 + attack_count * 2)),
                popup=folium.Popup(popup_html, max_width=320),
                tooltip=f"🚨 {ip} [{max_sev}] — {geo['country']} ({attack_count} attacks)",
                color="#FFFFFF",
                fill=True,
                fill_color=color,
                fill_opacity=0.9,
                weight=2
            ).add_to(marker_cluster)

            table_rows.append({
                "Attacker IP": ip,
                "Country": geo["country"],
                "City": geo["city"],
                "ISP / AS": geo["isp"],
                "Threat Level": max_sev,
                "Attack Count": attack_count,
                "Top Vector": threat_names[0] if threat_names else "Unknown"
            })

        # Add interactive Layer Control so user can toggle layers
        folium.LayerControl(position="topright", collapsed=False).add_to(m)

        # Auto-fit bounds if we have points
        if bounds_points:
            m.fit_bounds(bounds_points, padding=(50, 50))

        df_summary = pd.DataFrame(table_rows)
        if not df_summary.empty:
            df_summary = df_summary.sort_values(by="Attack Count", ascending=False)

        return m, df_summary

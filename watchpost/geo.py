"""Synthetic geolocation for demo IP ranges. Not a real geo lookup.

Only the RFC 5737 documentation ranges and RFC 1918 private ranges are mapped, each to a
fictional city at a fixed position. Anything else returns None ("unknown"): real addresses
are never guessed.
"""

import ipaddress
import math

# (network, fictional city, lat, lon)
_TABLE = [
    ("192.0.2.0/25", "Northhaven", 59.33, 18.07),
    ("192.0.2.128/25", "Saltmere", -33.87, 151.21),
    ("198.51.100.0/25", "Kestrel Bay", 35.68, 139.69),
    ("198.51.100.128/25", "Duskport", -23.55, -46.63),
    ("203.0.113.0/25", "Ironvale", 55.75, 37.62),
    ("203.0.113.128/25", "Emberfield", 6.52, 3.38),
    ("10.0.0.0/8", "Riverton HQ", 41.88, -87.63),
    ("172.16.0.0/12", "Lakeside branch", 47.61, -122.33),
    ("192.168.0.0/16", "Hillcrest remote site", 40.71, -74.01),
]
TABLE = [(ipaddress.ip_network(net), city, lat, lon) for net, city, lat, lon in _TABLE]
LABEL = "synthetic geo"
# RFC 1918 only. ipaddress's is_private also covers the RFC 5737 ranges, so it cannot be used here.
_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def locate(ip):
    """Return {"city", "lat", "lon", "synthetic": True} for a mapped address, else None."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for network, city, lat, lon in TABLE:
        if addr.version == network.version and addr in network:
            return {"city": city, "lat": lat, "lon": lon, "synthetic": True}
    return None


def is_internal(ip):
    """True for RFC 1918 addresses; the dashboard map draws those sites as the HQ target."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in _INTERNAL)


def distance_km(a, b):
    """Great-circle distance between two locate() results."""
    lat1, lon1, lat2, lon2 = map(math.radians, (a["lat"], a["lon"], b["lat"], b["lon"]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(min(1.0, h)))


# --- the HQ marker ----------------------------------------------------------------------
#
# The map draws one "HQ" marker and an arc to it from every attacking location. It used to sit
# wherever 10.0.0.0/8 happened to be mapped, which is a demo artefact rather than a fact about the
# installation. The operator picks the country instead (Admin > Map location) and the marker moves
# there. Coordinates are country centroids: precise enough for a world map, no lookup service.

COUNTRIES = {
    "AU": ("Australia", -25.27, 133.78),
    "AT": ("Austria", 47.52, 14.55),
    "BE": ("Belgium", 50.50, 4.47),
    "BR": ("Brazil", -14.24, -51.93),
    "CA": ("Canada", 56.13, -106.35),
    "CH": ("Switzerland", 46.82, 8.23),
    "CL": ("Chile", -35.68, -71.54),
    "CN": ("China", 35.86, 104.20),
    "CZ": ("Czechia", 49.82, 15.47),
    "DE": ("Germany", 51.17, 10.45),
    "DK": ("Denmark", 56.26, 9.50),
    "EE": ("Estonia", 58.60, 25.01),
    "ES": ("Spain", 40.46, -3.75),
    "FI": ("Finland", 61.92, 25.75),
    "FR": ("France", 46.23, 2.21),
    "GB": ("United Kingdom", 55.38, -3.44),
    "GR": ("Greece", 39.07, 21.82),
    "HK": ("Hong Kong", 22.32, 114.17),
    "HU": ("Hungary", 47.16, 19.50),
    "IE": ("Ireland", 53.14, -7.69),
    "IL": ("Israel", 31.05, 34.85),
    "IN": ("India", 20.59, 78.96),
    "IT": ("Italy", 41.87, 12.57),
    "JP": ("Japan", 36.20, 138.25),
    "KR": ("South Korea", 35.91, 127.77),
    "LT": ("Lithuania", 55.17, 23.88),
    "LU": ("Luxembourg", 49.82, 6.13),
    "LV": ("Latvia", 56.88, 24.60),
    "MX": ("Mexico", 23.63, -102.55),
    "MY": ("Malaysia", 4.21, 101.98),
    "NL": ("Netherlands", 52.13, 5.29),
    "NO": ("Norway", 60.47, 8.47),
    "NZ": ("New Zealand", -40.90, 174.89),
    "PL": ("Poland", 51.92, 19.15),
    "PT": ("Portugal", 39.40, -8.22),
    "RO": ("Romania", 45.94, 24.97),
    "RS": ("Serbia", 44.02, 21.01),
    "SE": ("Sweden", 60.13, 18.64),
    "SG": ("Singapore", 1.35, 103.82),
    "SI": ("Slovenia", 46.15, 14.99),
    "SK": ("Slovakia", 48.67, 19.70),
    "TR": ("Türkiye", 38.96, 35.24),
    "UA": ("Ukraine", 48.38, 31.17),
    "US": ("United States", 39.83, -98.58),
    "ZA": ("South Africa", -30.56, 22.94),
}
DEFAULT_COUNTRY = "US"
HQ_SETTING = "hq_country"


def hq_country(conn):
    """The configured HQ country code, or the default when nothing (valid) is stored."""
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (HQ_SETTING,)).fetchone()
    except Exception:  # a database old enough to have no settings table yet
        return DEFAULT_COUNTRY
    code = (row["value"] if row is not None else None) or ""
    code = code.strip().upper()
    return code if code in COUNTRIES else DEFAULT_COUNTRY


def hq(conn=None, country=None):
    """Where the map's HQ marker sits: {"city", "country", "lat", "lon", "internal", "synthetic"}."""
    if country is None:
        country = hq_country(conn) if conn is not None else DEFAULT_COUNTRY
    country = country.strip().upper()
    if country not in COUNTRIES:
        raise ValueError(f"unknown country code {country!r}")
    name, lat, lon = COUNTRIES[country]
    return {"city": f"{name} (HQ)", "country": country, "name": name,
            "lat": lat, "lon": lon, "internal": True, "synthetic": True}


def country_list():
    """Every selectable country, alphabetical by name, for the settings dropdown."""
    return [{"code": code, "name": name} for code, (name, _lat, _lon) in
            sorted(COUNTRIES.items(), key=lambda item: item[1][0])]

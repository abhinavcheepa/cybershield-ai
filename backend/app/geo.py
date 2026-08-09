"""Country catalog + IP geolocation.

The lat/lon table is what Leaflet draws arcs between, so it has to exist
regardless of the geo backend. Resolution uses a /16 prefix table covering the
ranges the simulator emits, then falls back to a deterministic hash so every IP
resolves to *something* stable.

Swapping in MaxMind GeoLite2 means replacing `lookup()` only — everything else
consumes the `GeoLocation` dataclass.
"""

from __future__ import annotations

import ipaddress
import zlib
from dataclasses import dataclass

# code -> (name, latitude, longitude, /16 prefix used by the simulator)
COUNTRIES: dict[str, tuple[str, float, float, str]] = {
    "RU": ("Russia", 55.75, 37.62, "185.220"),
    "CN": ("China", 39.90, 116.40, "223.104"),
    "US": ("United States", 38.90, -77.03, "104.28"),
    "IN": ("India", 28.61, 77.21, "103.21"),
    "BR": ("Brazil", -15.79, -47.88, "177.54"),
    "KP": ("North Korea", 39.03, 125.75, "175.45"),
    "IR": ("Iran", 35.69, 51.39, "5.160"),
    "NL": ("Netherlands", 52.37, 4.90, "94.102"),
    "DE": ("Germany", 52.52, 13.40, "78.46"),
    "FR": ("France", 48.86, 2.35, "51.83"),
    "GB": ("United Kingdom", 51.51, -0.13, "81.130"),
    "UA": ("Ukraine", 50.45, 30.52, "91.209"),
    "VN": ("Vietnam", 21.03, 105.85, "113.160"),
    "ID": ("Indonesia", -6.21, 106.85, "36.66"),
    "NG": ("Nigeria", 9.08, 7.40, "197.210"),
    "TR": ("Turkey", 39.93, 32.86, "95.70"),
    "KR": ("South Korea", 37.57, 126.98, "121.130"),
    "JP": ("Japan", 35.68, 139.69, "133.242"),
    "SG": ("Singapore", 1.35, 103.82, "128.199"),
    "AU": ("Australia", -35.28, 149.13, "139.130"),
    "CA": ("Canada", 45.42, -75.70, "142.44"),
    "ZA": ("South Africa", -25.75, 28.19, "41.76"),
    "MX": ("Mexico", 19.43, -99.13, "187.188"),
    "PL": ("Poland", 52.23, 21.01, "83.11"),
    "RO": ("Romania", 44.43, 26.10, "89.36"),
    "SE": ("Sweden", 59.33, 18.07, "155.4"),
}

_PREFIX_TO_CODE = {prefix: code for code, (_, _, _, prefix) in COUNTRIES.items()}
_ORDERED_CODES = sorted(COUNTRIES)

# The defended estate. Private RFC1918 traffic resolves here.
HOME = ("IN", "India", 28.61, 77.21)


@dataclass(frozen=True)
class GeoLocation:
    country_code: str
    country_name: str
    latitude: float
    longitude: float

    def as_source(self) -> dict:
        return {
            "source_country": self.country_code,
            "source_country_name": self.country_name,
            "source_lat": self.latitude,
            "source_lon": self.longitude,
        }

    def as_destination(self) -> dict:
        return {
            "destination_country": self.country_code,
            "destination_country_name": self.country_name,
            "destination_lat": self.latitude,
            "destination_lon": self.longitude,
        }


def _location(code: str) -> GeoLocation:
    name, lat, lon, _ = COUNTRIES[code]
    return GeoLocation(code, name, lat, lon)


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def lookup(ip: str) -> GeoLocation:
    """Resolve an IPv4 address to a country. Never raises."""
    if is_private(ip):
        return GeoLocation(*HOME)

    octets = ip.split(".")
    if len(octets) >= 2:
        code = _PREFIX_TO_CODE.get(f"{octets[0]}.{octets[1]}")
        if code:
            return _location(code)

    # Deterministic fallback: same IP always maps to the same country, so the
    # map does not flicker between page loads.
    index = zlib.crc32(ip.encode()) % len(_ORDERED_CODES)
    return _location(_ORDERED_CODES[index])


def ip_for_country(code: str, rng) -> str:
    """Build an address inside `code`'s prefix so `lookup()` round-trips."""
    prefix = COUNTRIES.get(code, COUNTRIES["RU"])[3]
    return f"{prefix}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


def country_choices() -> list[dict]:
    return [
        {"code": code, "name": name, "latitude": lat, "longitude": lon}
        for code, (name, lat, lon, _) in sorted(COUNTRIES.items(), key=lambda kv: kv[1][0])
    ]


if __name__ == "__main__":
    import random

    rng = random.Random(7)
    for code in COUNTRIES:
        assert lookup(ip_for_country(code, rng)).country_code == code, code
    assert lookup("10.0.0.5").country_code == HOME[0]
    assert lookup("8.8.8.8").country_code == lookup("8.8.8.8").country_code
    print(f"geo ok: {len(COUNTRIES)} countries round-trip")

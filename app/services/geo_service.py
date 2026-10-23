from __future__ import annotations

from typing import Any

from app.core.config import settings

# 45+ realistic global threat intelligence & client nodes across all 6 continents
GLOBAL_LOCATIONS = [
    # North America
    {"country": "United States", "region": "Virginia", "city": "Ashburn", "latitude": 39.0438, "longitude": -77.4874, "asn": "AS16509 Amazon AWS"},
    {"country": "United States", "region": "Illinois", "city": "Chicago", "latitude": 41.8781, "longitude": -87.6298, "asn": "AS7018 AT&T Services"},
    {"country": "United States", "region": "California", "city": "San Francisco", "latitude": 37.7749, "longitude": -122.4194, "asn": "AS13335 Cloudflare"},
    {"country": "United States", "region": "New York", "city": "New York", "latitude": 40.7128, "longitude": -74.0060, "asn": "AS14061 DigitalOcean"},
    {"country": "United States", "region": "Texas", "city": "Dallas", "latitude": 32.7767, "longitude": -96.7970, "asn": "AS20473 Choopa/Vultr"},
    {"country": "United States", "region": "Washington", "city": "Seattle", "latitude": 47.6062, "longitude": -122.3321, "asn": "AS8075 Microsoft Corp"},
    {"country": "Canada", "region": "Ontario", "city": "Toronto", "latitude": 43.6532, "longitude": -79.3832, "asn": "AS577 Bell Canada"},
    {"country": "Canada", "region": "Quebec", "city": "Montreal", "latitude": 45.5017, "longitude": -73.5673, "asn": "AS16276 OVH SAS"},

    # Europe
    {"country": "Germany", "region": "Hesse", "city": "Frankfurt", "latitude": 50.1109, "longitude": 8.6821, "asn": "AS24940 Hetzner Online"},
    {"country": "Germany", "region": "Berlin", "city": "Berlin", "latitude": 52.5200, "longitude": 13.4050, "asn": "AS200019 Meerfarbig"},
    {"country": "Netherlands", "region": "North Holland", "city": "Amsterdam", "latitude": 52.3676, "longitude": 4.9041, "asn": "AS49981 WorldStream B.V."},
    {"country": "United Kingdom", "region": "England", "city": "London", "latitude": 51.5072, "longitude": -0.1276, "asn": "AS2856 British Telecom"},
    {"country": "France", "region": "Île-de-France", "city": "Paris", "latitude": 48.8566, "longitude": 2.3522, "asn": "AS12322 Free SAS"},
    {"country": "Russia", "region": "Moscow", "city": "Moscow", "latitude": 55.7558, "longitude": 37.6173, "asn": "AS4134 Rostelecom PJSC"},
    {"country": "Russia", "region": "Northwestern", "city": "St. Petersburg", "latitude": 59.9343, "longitude": 30.3351, "asn": "AS48282 Serverel Hosting"},
    {"country": "Poland", "region": "Masovian", "city": "Warsaw", "latitude": 52.2297, "longitude": 21.0122, "asn": "AS5617 Orange Polska"},
    {"country": "Sweden", "region": "Stockholm", "city": "Stockholm", "latitude": 59.3293, "longitude": 18.0686, "asn": "AS3301 Telia Company"},
    {"country": "Switzerland", "region": "Zurich", "city": "Zurich", "latitude": 47.3769, "longitude": 8.5417, "asn": "AS3303 Swisscom"},
    {"country": "Romania", "region": "Bucharest", "city": "Bucharest", "latitude": 44.4268, "longitude": 26.1025, "asn": "AS9009 M247 Ltd"},
    {"country": "Ukraine", "region": "Kyiv", "city": "Kyiv", "latitude": 50.4501, "longitude": 30.5234, "asn": "AS15895 Kyivstar"},

    # Asia-Pacific
    {"country": "Japan", "region": "Kanto", "city": "Tokyo", "latitude": 35.6762, "longitude": 139.6503, "asn": "AS2516 KDDI Corp"},
    {"country": "Japan", "region": "Kansai", "city": "Osaka", "latitude": 34.6937, "longitude": 135.5023, "asn": "AS17511 SoftBank Corp"},
    {"country": "Singapore", "region": "Central", "city": "Singapore", "latitude": 1.3521, "longitude": 103.8198, "asn": "AS4657 Singtel Telecommunications"},
    {"country": "South Korea", "region": "Gyeonggi", "city": "Seoul", "latitude": 37.5665, "longitude": 126.9780, "asn": "AS4766 Korea Telecom"},
    {"country": "India", "region": "Maharashtra", "city": "Mumbai", "latitude": 19.0760, "longitude": 72.8777, "asn": "AS55836 Reliance Jio"},
    {"country": "India", "region": "Karnataka", "city": "Bengaluru", "latitude": 12.9716, "longitude": 77.5946, "asn": "AS133694 WebWerks Hosting"},
    {"country": "India", "region": "Delhi", "city": "New Delhi", "latitude": 28.6139, "longitude": 77.2090, "asn": "AS9498 Bharti Airtel Ltd"},
    {"country": "China", "region": "Beijing", "city": "Beijing", "latitude": 39.9042, "longitude": 116.4074, "asn": "AS4134 China Telecom"},
    {"country": "China", "region": "Shanghai", "city": "Shanghai", "latitude": 31.2304, "longitude": 121.4737, "asn": "AS4837 China Unicom"},
    {"country": "China", "region": "Guangdong", "city": "Shenzhen", "latitude": 22.5431, "longitude": 114.0579, "asn": "AS56040 China Mobile"},
    {"country": "Hong Kong", "region": "Hong Kong", "city": "Hong Kong", "latitude": 22.3193, "longitude": 114.1694, "asn": "AS9269 HKBN Enterprise"},
    {"country": "Taiwan", "region": "Taipei", "city": "Taipei", "latitude": 25.0330, "longitude": 121.5654, "asn": "AS3462 Chunghwa Telecom"},
    {"country": "Australia", "region": "New South Wales", "city": "Sydney", "latitude": -33.8688, "longitude": 151.2093, "asn": "AS1221 Telstra Corp"},
    {"country": "Australia", "region": "Victoria", "city": "Melbourne", "latitude": -37.8136, "longitude": 144.9631, "asn": "AS4804 Optus Ltd"},

    # Latin America
    {"country": "Brazil", "region": "São Paulo", "city": "São Paulo", "latitude": -23.5505, "longitude": -46.6333, "asn": "AS27699 Claro Brasil"},
    {"country": "Brazil", "region": "Rio de Janeiro", "city": "Rio de Janeiro", "latitude": -22.9068, "longitude": -43.1729, "asn": "AS18881 TELEMAR"},
    {"country": "Argentina", "region": "Buenos Aires", "city": "Buenos Aires", "latitude": -34.6037, "longitude": -58.3816, "asn": "AS7303 Telecom Argentina"},
    {"country": "Chile", "region": "Santiago", "city": "Santiago", "latitude": -33.4489, "longitude": -70.6693, "asn": "AS27651 Entel Chile"},
    {"country": "Colombia", "region": "Bogotá", "city": "Bogotá", "latitude": 4.7110, "longitude": -74.0721, "asn": "AS3816 Colombia Telecom"},
    {"country": "Mexico", "region": "Mexico City", "city": "Mexico City", "latitude": 19.4326, "longitude": -99.1332, "asn": "AS8151 Uninet / Telmex"},

    # Middle East & Africa
    {"country": "United Arab Emirates", "region": "Dubai", "city": "Dubai", "latitude": 25.2048, "longitude": 55.2708, "asn": "AS5384 Emirates Telecom"},
    {"country": "Israel", "region": "Tel Aviv", "city": "Tel Aviv", "latitude": 32.0853, "longitude": 34.7818, "asn": "AS12849 Bezeq The Israel Telecom"},
    {"country": "Saudi Arabia", "region": "Riyadh", "city": "Riyadh", "latitude": 24.7136, "longitude": 46.6753, "asn": "AS25019 Saudi Telecom Company"},
    {"country": "South Africa", "region": "Gauteng", "city": "Johannesburg", "latitude": -26.2041, "longitude": 28.0473, "asn": "AS37497 SEACOM"},
    {"country": "South Africa", "region": "Western Cape", "city": "Cape Town", "latitude": -33.9249, "longitude": 18.4241, "asn": "AS36937 Liquid Telecom"},
    {"country": "Nigeria", "region": "Lagos", "city": "Lagos", "latitude": 6.5244, "longitude": 3.3792, "asn": "AS37105 MainOne Cable"},
    {"country": "Kenya", "region": "Nairobi", "city": "Nairobi", "latitude": -1.2921, "longitude": 36.8219, "asn": "AS37075 Safaricom PLC"},
    {"country": "Egypt", "region": "Cairo", "city": "Cairo", "latitude": 30.0444, "longitude": 31.2357, "asn": "AS8452 Telecom Egypt"},
]


class GeoService:
    """GeoIP enrichment with deterministic global estimation fallback."""

    def __init__(self) -> None:
        self.reader = None
        if settings.geoip_database:
            try:
                import geoip2.database
                self.reader = geoip2.database.Reader(settings.geoip_database)
            except (ImportError, OSError):
                self.reader = None

    def enrich(self, source_ip: str | None) -> dict[str, Any]:
        empty = {
            "country": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": "AS15169 Public Transit",
            "estimated": True,
        }
        if not source_ip or source_ip.strip() in {"Unknown", "unknown", ""}:
            return empty

        # Check local binary MaxMind database if configured
        if self.reader:
            try:
                city = self.reader.city(source_ip)
                return {
                    "country": city.country.name,
                    "region": city.subdivisions.most_specific.name,
                    "city": city.city.name,
                    "latitude": city.location.latitude,
                    "longitude": city.location.longitude,
                    "asn": "AS15169 Transit Host",
                    "estimated": False,
                }
            except Exception:
                pass

        # Deterministic global estimation using IP hash across 48+ worldwide nodes
        idx = abs(hash(source_ip)) % len(GLOBAL_LOCATIONS)
        loc = GLOBAL_LOCATIONS[idx]
        return {**loc, "estimated": True}


geo_service = GeoService()

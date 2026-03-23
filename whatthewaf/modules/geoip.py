"""IP geolocation via ip-api.com (free, no API key needed).

Supports bulk queries (up to 100 IPs per batch).
Rate limit: 45 requests/minute for single, 15/minute for batch.
"""

import httpx
import json


def geolocate_ip(ip, timeout=5):
    """Geolocate a single IP address.

    Returns dict: ip, country, country_code, region, city, lat, lon, isp, org, as_info
    """
    try:
        r = httpx.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
            timeout=timeout,
        )
        data = r.json()
        if data.get("status") == "success":
            return {
                "ip": ip,
                "country": data.get("country", ""),
                "country_code": data.get("countryCode", ""),
                "region": data.get("regionName", ""),
                "region_code": data.get("region", ""),
                "city": data.get("city", ""),
                "zip": data.get("zip", ""),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
                "timezone": data.get("timezone", ""),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
                "as_info": data.get("as", ""),
            }
    except Exception:
        pass

    return _unknown(ip)


def geolocate_bulk(ips, timeout=10):
    """Geolocate multiple IPs in one batch request (max 100).

    Returns list of geo dicts in same order as input.
    """
    if not ips:
        return []

    # Deduplicate while preserving order
    unique_ips = list(dict.fromkeys(ips))

    # ip-api.com batch endpoint accepts POST with JSON array
    try:
        payload = [
            {"query": ip, "fields": "status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"}
            for ip in unique_ips[:100]
        ]
        r = httpx.post(
            "http://ip-api.com/batch",
            json=payload,
            timeout=timeout,
        )
        results_raw = r.json()

        results_map = {}
        for data in results_raw:
            ip = data.get("query", "")
            if data.get("status") == "success":
                results_map[ip] = {
                    "ip": ip,
                    "country": data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "region": data.get("regionName", ""),
                    "region_code": data.get("region", ""),
                    "city": data.get("city", ""),
                    "zip": data.get("zip", ""),
                    "lat": data.get("lat", 0),
                    "lon": data.get("lon", 0),
                    "timezone": data.get("timezone", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "as_info": data.get("as", ""),
                }
            else:
                results_map[ip] = _unknown(ip)

        # Return in original order, including duplicates
        return [results_map.get(ip, _unknown(ip)) for ip in ips]

    except Exception:
        # Fallback to individual lookups
        return [geolocate_ip(ip, timeout=timeout) for ip in ips]


def _unknown(ip):
    return {
        "ip": ip,
        "country": "",
        "country_code": "",
        "region": "",
        "region_code": "",
        "city": "",
        "zip": "",
        "lat": 0,
        "lon": 0,
        "timezone": "",
        "isp": "",
        "org": "",
        "as_info": "",
    }

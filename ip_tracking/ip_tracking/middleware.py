from __future__ import annotations

from typing import Optional, Tuple

import requests
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin

from .models import BlockedIP, RequestLog


CACHE_TTL_SECONDS = 60 * 60 * 24  # 24 hours


def get_client_ip(request) -> str:
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        # Comma-separated list; first is original client in typical proxy setups
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def fetch_geolocation(ip: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Fetch geolocation for an IP using a simple JSON API.
    Returns (country, city) or (None, None) on failure.

    We keep it defensive: API outages must not break the request flow.
    """
    # ip-api JSON endpoint: http(s)://ip-api.com/json/{query}
    url = f"http://ip-api.com/json/{ip}"
    params = {
        "fields": "status,country,city,message",
    }

    try:
        resp = requests.get(url, params=params, timeout=2.0)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return (None, None)

    if data.get("status") != "success":
        return (None, None)

    country = data.get("country") or None
    city = data.get("city") or None
    return (country, city)


def get_geolocation_cached(ip: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Cache geolocation lookups for 24h to reduce API calls and latency.
    """
    cache_key = f"ip_geo:{ip}"
    cached = cache.get(cache_key)
    if isinstance(cached, dict):
        return (cached.get("country"), cached.get("city"))

    country, city = fetch_geolocation(ip)
    cache.set(cache_key, {"country": country, "city": city}, CACHE_TTL_SECONDS)
    return (country, city)

# ip_tracking/middleware.py

class IPTrackingMiddleware:  # <--- Note this name
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # We import inside the method to avoid loading issues
        from .models import RequestLog
        
        # Your tracking logic here...
        
        return self.get_response(request)
    

class IPLoggingMiddleware(MiddlewareMixin):
    """
    Task 0 + Task 1 + Task 2:
    - Block blacklisted IPs (403)
    - Log each request (ip, timestamp, path)
    - Add geolocation (country, city) with 24h caching
    """

    def process_request(self, request):
        ip = get_client_ip(request)
        path = request.path

        if not ip:
            return None

        # Task 1: block first
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Forbidden: Your IP is blocked.")

        # Task 2: geolocate with cache
        country, city = get_geolocation_cached(ip)

        # Task 0: log
        RequestLog.objects.create(
            ip_address=ip,
            path=path,
            country=country,
            city=city,
        )

        return None

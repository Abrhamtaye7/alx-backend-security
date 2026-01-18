from __future__ import annotations

from datetime import timedelta

from celery import shared_task
from django.db.models import Count, Q
from django.utils import timezone

from ip_tracking.models import RequestLog, SuspiciousIP


SENSITIVE_PATH_PREFIXES = ("/admin", "/login")
HOURLY_THRESHOLD = 100


@shared_task
def detect_suspicious_ips() -> dict:
    """
    Runs hourly:
    - Flags IPs exceeding 100 requests in the last hour
    - Flags IPs that accessed sensitive paths (/admin, /login) in the last hour

    Returns a small summary dict (useful for logs/monitoring).
    """
    now = timezone.now()
    since = now - timedelta(hours=1)

    recent_logs = RequestLog.objects.filter(timestamp__gte=since)

    # 1) High volume IPs (> 100 requests/hour)
    high_volume = (
        recent_logs.values("ip_address")
        .annotate(req_count=Count("id"))
        .filter(req_count__gt=HOURLY_THRESHOLD)
    )

    flagged_count = 0

    for row in high_volume:
        ip = row["ip_address"]
        count = row["req_count"]
        reason = f"High traffic: {count} requests in the last hour"

        SuspiciousIP.objects.update_or_create(
            ip_address=ip,
            defaults={"reason": reason},
        )
        flagged_count += 1

    # 2) Sensitive path access in the last hour
    # Build a Q object for prefixes: path startswith "/admin" OR "/login"
    q = Q()
    for prefix in SENSITIVE_PATH_PREFIXES:
        q |= Q(path__startswith=prefix)

    sensitive_hits = (
        recent_logs.filter(q)
        .values("ip_address")
        .annotate(hit_count=Count("id"))
    )

    for row in sensitive_hits:
        ip = row["ip_address"]
        hit_count = row["hit_count"]
        reason = f"Sensitive path access: {hit_count} hits to {SENSITIVE_PATH_PREFIXES} in the last hour"

        # If already flagged for high volume, append/merge reasons without losing previous info
        obj, created = SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            defaults={"reason": reason},
        )
        if not created and reason not in obj.reason:
            obj.reason = f"{obj.reason} | {reason}"
            obj.save(update_fields=["reason", "last_seen_at"])
        elif created:
            flagged_count += 1

    return {
        "since": since.isoformat(),
        "flagged_total": SuspiciousIP.objects.filter(last_seen_at__gte=since).count(),
        "new_or_updated_this_run": flagged_count,
    }

from django.http import HttpResponse
from django_ratelimit.decorators import ratelimit


def login_rate(group, request):
    """
    Callable 'rate' for django-ratelimit:
    - authenticated users: 10 requests/minute
    - anonymous users: 5 requests/minute
    """
    if request.user.is_authenticated:
        return "10/m"
    return "5/m"


@ratelimit(
    key="user_or_ip",
    rate=login_rate,      # callable rate (auth-aware)
    method="POST",        # typical: limit login submissions, not GET of the page
    block=True,           # block -> raises a 403 by default
)
def login_view(request):
    """
    Example sensitive endpoint to protect.
    Replace the body with your real login logic (or wrap your existing login view).
    """
    if request.method == "GET":
        return HttpResponse("Login page (GET).")

    # POST (login attempt)
    return HttpResponse("Login attempt received (POST).")

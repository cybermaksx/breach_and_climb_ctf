import hashlib
from decimal import Decimal, InvalidOperation

AVATAR_COLORS = ["#1f3a5f", "#7a2e2e", "#2e5e4e", "#5b3f7a", "#7a5a1f", "#28536b", "#6b2851", "#3d5a1f"]


def money(cents):
    cents = cents or 0
    return f"{cents / 100:,.2f}"


def initials(name):
    parts = [p for p in (name or "?").split() if p]
    return "".join(p[0] for p in parts[:2]).upper()


def avatar_color(seed):
    digest = hashlib.md5(str(seed).encode()).digest()
    return AVATAR_COLORS[digest[0] % len(AVATAR_COLORS)]


def short_dt(value):
    return (value or "")[:16]


def parse_amount(raw):
    """Convert user input like '1,250.50' into integer cents. Returns None if invalid."""
    try:
        value = Decimal((raw or "").replace(",", "").strip())
    except InvalidOperation:
        return None
    if not value.is_finite() or value <= 0 or value > Decimal("10000000"):
        return None
    cents = value * 100
    if cents != cents.to_integral_value():
        return None
    return int(cents)


def init_app(app):
    app.add_template_filter(money)
    app.add_template_filter(initials)
    app.add_template_filter(avatar_color)
    app.add_template_filter(short_dt)

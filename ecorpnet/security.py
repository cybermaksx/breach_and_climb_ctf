"""Session-bound CSRF protection and HTTP security headers."""
import hmac
import secrets

from flask import abort, request, session

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)


def get_csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


def init_app(app):
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    if app.config.get("SESSION_COOKIE_SAMESITE") is None:  # Flask's default is None
        app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    @app.before_request
    def csrf_protect():
        if request.method != "POST" or request.path.startswith("/api/"):
            return
        expected = session.get("_csrf", "")
        sent = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected, sent):
            abort(400, description="Your session expired. Reload the page and try again.")

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        if request.endpoint != "static":
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.context_processor
    def inject_csrf():
        return {"csrf_token": get_csrf_token}

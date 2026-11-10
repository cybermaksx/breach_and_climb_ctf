import functools
import re

from flask import Blueprint, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db
from .security import get_csrf_token

bp = Blueprint("auth", __name__)

# Document clearance / general privilege level per role.
ROLE_LEVEL = {"contractor": 0, "employee": 1, "it": 1, "manager": 2, "admin": 3}
ROLE_LABELS = {
    "contractor": "Contractor",
    "employee": "Employee",
    "it": "IT Staff",
    "manager": "Manager",
    "admin": "Administrator",
}
USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Brute-force protection inside the window: per (IP, username) and per IP (password spraying).
MAX_FAILED_LOGINS = 10
MAX_FAILED_PER_IP = 30
LOCKOUT_WINDOW = "-10 minutes"
# Self-registration limits.
MAX_REGISTRATIONS_PER_IP = 5
REGISTRATION_WINDOW = "-1 hour"
CORPORATE_DOMAIN = "e-corp.com"
RESERVED_USERNAMES = {
    "admin", "administrator", "root", "system", "sysadmin", "support", "helpdesk", "it", "itsupport",
    "security", "soc", "hr", "payroll", "finance", "legal", "ceo", "cto", "noreply", "postmaster", "ecorp",
}
RESERVED_PREFIXES = ("admin", "it-", "it.", "it_", "helpdesk", "support", "security", "hr-", "hr.", "payroll", "ecorp")
# Hash checked when the username does not exist, so response time does not reveal valid usernames.
_DUMMY_HASH = generate_password_hash("ecorpnet-dummy-password")


def level(user):
    return ROLE_LEVEL.get(user["role"], 0)


def revoke_sessions(db, user_id):
    """Invalidate every existing session cookie of a user (logout, password change, disable)."""
    db.execute("UPDATE users SET session_epoch = session_epoch + 1 WHERE id = ?", (user_id,))


@bp.before_app_request
def load_logged_in_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is None:
        return
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is not None and user["is_active"] and session.get("epoch") == user["session_epoch"]:
        g.user = user
    else:
        session.clear()


@bp.app_context_processor
def inject_roles():
    return {"ROLE_LABELS": ROLE_LABELS, "role_level": level}


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def roles_required(*roles):
    def decorator(view):
        @functools.wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def _safe_next(target):
    # Only same-site absolute paths. Browsers treat "\" like "/" and ignore tabs/newlines,
    # so "/\evil.com" or "/\t/evil.com" would become protocol-relative URLs.
    if (
        target
        and target.startswith("/")
        and not target.startswith("//")
        and "\\" not in target
        and not any(ord(ch) < 32 for ch in target)
    ):
        return target
    return url_for("main.dashboard")


def _too_many_failures(db, ip, username):
    per_user, per_ip = db.execute(
        "SELECT COALESCE(SUM(username = ?), 0), COUNT(*) FROM login_attempts"
        " WHERE ip = ? AND created_at > datetime('now', ?)",
        (username, ip, LOCKOUT_WINDOW),
    ).fetchone()
    return per_user >= MAX_FAILED_LOGINS or per_ip >= MAX_FAILED_PER_IP


def _reserved_username(username):
    return username in RESERVED_USERNAMES or username.startswith(RESERVED_PREFIXES)


@bp.route("/login", methods=("GET", "POST"))
def login():
    if g.user:
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()[:64]
        password = request.form.get("password", "")
        ip = request.remote_addr or ""
        db = get_db()
        if _too_many_failures(db, ip, username):
            flash("Too many failed sign-in attempts. Try again in 10 minutes.", "error")
            return render_template("auth/login.html"), 429
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        password_ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
        if user is None or not password_ok:
            db.execute("INSERT INTO login_attempts (ip, username) VALUES (?, ?)", (ip, username))
            db.execute("DELETE FROM login_attempts WHERE created_at < datetime('now', '-1 day')")
            db.commit()
            flash("Invalid username or password.", "error")
        elif not user["is_active"]:
            flash("This account has been disabled. Contact IT Operations.", "error")
        else:
            db.execute("DELETE FROM login_attempts WHERE ip = ? AND username = ?", (ip, username))
            db.execute("UPDATE users SET last_login = datetime('now') WHERE id = ?", (user["id"],))
            db.commit()
            session.clear()
            session["user_id"] = user["id"]
            session["epoch"] = user["session_epoch"]
            session["prev_login"] = user["last_login"]
            get_csrf_token()
            return redirect(_safe_next(request.args.get("next")))
    return render_template("auth/login.html")


@bp.route("/register", methods=("GET", "POST"))
def register():
    if g.user:
        return redirect(url_for("main.dashboard"))
    form = request.form
    if request.method == "POST":
        username = form.get("username", "").strip().lower()
        full_name = form.get("full_name", "").strip()
        email = form.get("email", "").strip().lower()
        company = form.get("company", "").strip()
        password = form.get("password", "")
        errors = []
        if not USERNAME_RE.match(username):
            errors.append("Username must be 3-32 characters: a-z, 0-9, dot, dash, underscore.")
        elif _reserved_username(username):
            errors.append("That username is reserved.")
        if not 2 <= len(full_name) <= 80:
            errors.append("Please enter your full name.")
        if not EMAIL_RE.match(email) or len(email) > 120:
            errors.append("Please enter a valid email address.")
        elif email.rsplit("@", 1)[1] == CORPORATE_DOMAIN or email.endswith("." + CORPORATE_DOMAIN):
            errors.append("E Corp employees already have an account. Contractors must use their company email.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != form.get("confirm", ""):
            errors.append("Passwords do not match.")

        db = get_db()
        ip = request.remote_addr or ""
        recent = db.execute(
            "SELECT COUNT(*) FROM users WHERE registration_ip = ? AND created_at > datetime('now', ?)",
            (ip, REGISTRATION_WINDOW),
        ).fetchone()[0]
        if recent >= MAX_REGISTRATIONS_PER_IP:
            flash("Too many accounts were created from your network. Try again later.", "error")
            return render_template("auth/register.html", form=form), 429
        if not errors and db.execute(
            "SELECT 1 FROM users WHERE username = ? OR email = ?", (username, email)
        ).fetchone():
            errors.append("That username or email is already registered.")

        if errors:
            for e in errors:
                flash(e, "error")
        else:
            title = f"External Contractor ({company[:60]})" if company else "External Contractor"
            db.execute(
                "INSERT INTO users (username, password_hash, full_name, email, role, department, title,"
                " registration_ip) VALUES (?, ?, ?, ?, 'contractor', 'Contractors', ?, ?)",
                (username, generate_password_hash(password), full_name, email, title, ip),
            )
            db.commit()
            flash("Contractor account created. You can now sign in.", "success")
            return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form)


@bp.route("/logout", methods=("POST",))
def logout():
    if g.user:
        db = get_db()
        revoke_sessions(db, g.user["id"])
        db.commit()
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))

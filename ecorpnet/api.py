"""JSON API used by the ECorpNet front-end widgets and internal tooling."""
import functools

from flask import Blueprint, abort, g, jsonify, request

from .db import get_db

bp = Blueprint("api", __name__, url_prefix="/api/v1")

PUBLIC_FIELDS = ("id", "username", "full_name", "email", "title", "department", "phone", "office", "manager_id")


def api_login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return jsonify(error="authentication required"), 401
        return view(*args, **kwargs)

    return wrapped


def public(row):
    return {k: row[k] for k in PUBLIC_FIELDS}


@bp.errorhandler(404)
def not_found(e):
    return jsonify(error="not found"), 404


@bp.route("/")
def index():
    return jsonify(
        service="ECorpNet API",
        version="1.4.2",
        endpoints=["/api/v1/me", "/api/v1/employees", "/api/v1/employees/<id>", "/api/v1/wallet", "/api/v1/tickets"],
    )


@bp.route("/me")
@api_login_required
def me():
    data = public(g.user)
    data.update(role=g.user["role"], balance=g.user["balance"] / 100, last_login=g.user["last_login"])
    return jsonify(data)


@bp.route("/employees")
@api_login_required
def employees():
    q = request.args.get("q", "").strip()
    sql = f"SELECT {', '.join(PUBLIC_FIELDS)} FROM users WHERE is_active = 1"
    if q:
        # Intentional CTF vulnerability: the legacy employee search interpolates input.
        sql += f" AND (full_name LIKE '%{q}%' OR username LIKE '%{q}%' OR department LIKE '%{q}%')"
    rows = get_db().execute(sql + " ORDER BY full_name LIMIT 100").fetchall()
    return jsonify([public(r) for r in rows])


@bp.route("/employees/<int:user_id>")
@api_login_required
def employee(user_id):
    row = get_db().execute(
        f"SELECT {', '.join(PUBLIC_FIELDS)} FROM users WHERE id = ? AND is_active = 1", (user_id,)
    ).fetchone()
    if row is None:
        abort(404)
    return jsonify(public(row))


@bp.route("/wallet")
@api_login_required
def wallet():
    uid = g.user["id"]
    rows = get_db().execute(
        "SELECT id, sender_id, recipient_id, amount, kind, memo, created_at FROM transactions"
        " WHERE sender_id = ? OR recipient_id = ? ORDER BY id DESC LIMIT 20",
        (uid, uid),
    ).fetchall()
    return jsonify(
        balance=g.user["balance"] / 100,
        currency="EC",
        transactions=[dict(r, amount=r["amount"] / 100) for r in rows],
    )


@bp.route("/tickets")
@api_login_required
def tickets():
    rows = get_db().execute(
        "SELECT id, subject, category, priority, status, created_at, updated_at FROM tickets"
        " WHERE author_id = ? ORDER BY id DESC",
        (g.user["id"],),
    ).fetchall()
    return jsonify([dict(r) for r in rows])

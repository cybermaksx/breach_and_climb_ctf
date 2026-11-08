from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from .auth import login_required
from .db import get_db

bp = Blueprint("tickets", __name__, url_prefix="/tickets")

CATEGORIES = ["Hardware", "Software", "Network / VPN", "Access Request", "Email", "Security Incident", "Other"]
PRIORITIES = ["low", "normal", "high", "critical"]
STATUSES = ["open", "in_progress", "resolved", "closed"]
STAFF_ROLES = ("it", "admin")


def is_staff(user):
    return user["role"] in STAFF_ROLES


def get_ticket(ticket_id):
    ticket = get_db().execute(
        "SELECT t.*, a.full_name AS author_name, a.department AS author_department,"
        " s.full_name AS assignee_name FROM tickets t JOIN users a ON a.id = t.author_id"
        " LEFT JOIN users s ON s.id = t.assignee_id WHERE t.id = ?",
        (ticket_id,),
    ).fetchone()
    if ticket is None:
        abort(404)
    if ticket["author_id"] != g.user["id"] and not is_staff(g.user):
        abort(403)
    return ticket


@bp.route("/")
@login_required
def index():
    db = get_db()
    status = request.args.get("status", "")
    scope = request.args.get("scope", "all" if is_staff(g.user) else "mine")
    sql = (
        "SELECT t.*, a.full_name AS author_name, s.full_name AS assignee_name FROM tickets t"
        " JOIN users a ON a.id = t.author_id LEFT JOIN users s ON s.id = t.assignee_id WHERE 1 = 1"
    )
    params = []
    if not is_staff(g.user) or scope == "mine":
        sql += " AND t.author_id = ?"
        params.append(g.user["id"])
    elif scope == "assigned":
        sql += " AND t.assignee_id = ?"
        params.append(g.user["id"])
    if status in STATUSES:
        sql += " AND t.status = ?"
        params.append(status)
    sql += " ORDER BY CASE t.status WHEN 'open' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END, t.updated_at DESC"
    tickets = db.execute(sql, params).fetchall()
    return render_template("tickets/index.html", tickets=tickets, status=status, scope=scope, STATUSES=STATUSES)


@bp.route("/new", methods=("GET", "POST"))
@login_required
def new():
    form = request.form
    if request.method == "POST":
        subject = form.get("subject", "").strip()
        body = form.get("body", "").strip()
        category = form.get("category", "")
        priority = form.get("priority", "normal")
        if not subject or not body:
            flash("Subject and description are required.", "error")
        elif category not in CATEGORIES or priority not in PRIORITIES:
            flash("Invalid category or priority.", "error")
        else:
            db = get_db()
            cur = db.execute(
                "INSERT INTO tickets (author_id, subject, category, priority, body) VALUES (?, ?, ?, ?, ?)",
                (g.user["id"], subject[:200], category, priority, body[:10000]),
            )
            db.commit()
            flash(f"Ticket #{cur.lastrowid} submitted to IT Operations.", "success")
            return redirect(url_for("tickets.view", ticket_id=cur.lastrowid))
    return render_template("tickets/new.html", form=form, CATEGORIES=CATEGORIES, PRIORITIES=PRIORITIES)


@bp.route("/<int:ticket_id>")
@login_required
def view(ticket_id):
    ticket = get_ticket(ticket_id)
    db = get_db()
    comments = db.execute(
        "SELECT c.*, u.full_name AS author_name, u.role AS author_role FROM ticket_comments c"
        " JOIN users u ON u.id = c.author_id WHERE c.ticket_id = ? ORDER BY c.id",
        (ticket_id,),
    ).fetchall()
    staff = db.execute(
        "SELECT id, full_name FROM users WHERE role IN ('it', 'admin') AND is_active = 1 ORDER BY full_name"
    ).fetchall()
    return render_template(
        "tickets/view.html",
        ticket=ticket,
        comments=comments,
        staff=staff,
        is_staff=is_staff(g.user),
        STATUSES=STATUSES,
        PRIORITIES=PRIORITIES,
    )


@bp.route("/<int:ticket_id>/comment", methods=("POST",))
@login_required
def comment(ticket_id):
    ticket = get_ticket(ticket_id)
    body = request.form.get("body", "").strip()
    if not body:
        flash("Comment cannot be empty.", "error")
    elif ticket["status"] == "closed":
        flash("This ticket is closed.", "error")
    else:
        db = get_db()
        db.execute(
            "INSERT INTO ticket_comments (ticket_id, author_id, body) VALUES (?, ?, ?)",
            (ticket_id, g.user["id"], body[:5000]),
        )
        db.execute("UPDATE tickets SET updated_at = datetime('now') WHERE id = ?", (ticket_id,))
        db.commit()
    return redirect(url_for("tickets.view", ticket_id=ticket_id) + "#comments")


@bp.route("/<int:ticket_id>/update", methods=("POST",))
@login_required
def update(ticket_id):
    get_ticket(ticket_id)
    if not is_staff(g.user):
        abort(403)
    status = request.form.get("status")
    priority = request.form.get("priority")
    assignee = request.form.get("assignee_id") or None
    if status not in STATUSES or priority not in PRIORITIES:
        abort(400)
    db = get_db()
    if assignee is not None and not db.execute(
        "SELECT 1 FROM users WHERE id = ? AND role IN ('it', 'admin')", (assignee,)
    ).fetchone():
        abort(400)
    db.execute(
        "UPDATE tickets SET status = ?, priority = ?, assignee_id = ?, updated_at = datetime('now') WHERE id = ?",
        (status, priority, assignee, ticket_id),
    )
    db.commit()
    flash("Ticket updated.", "success")
    return redirect(url_for("tickets.view", ticket_id=ticket_id))


@bp.route("/<int:ticket_id>/close", methods=("POST",))
@login_required
def close(ticket_id):
    ticket = get_ticket(ticket_id)
    if ticket["author_id"] != g.user["id"] and not is_staff(g.user):
        abort(403)
    db = get_db()
    db.execute("UPDATE tickets SET status = 'closed', updated_at = datetime('now') WHERE id = ?", (ticket_id,))
    db.commit()
    flash("Ticket closed.", "success")
    return redirect(url_for("tickets.view", ticket_id=ticket_id))

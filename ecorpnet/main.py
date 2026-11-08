from flask import Blueprint, g, render_template

from .auth import level, login_required
from .db import get_db
from .documents import allowed_clearances

bp = Blueprint("main", __name__)


@bp.route("/")
@login_required
def dashboard():
    db = get_db()
    uid = g.user["id"]
    announcements = db.execute(
        "SELECT a.*, u.full_name AS author_name, u.title AS author_title FROM announcements a"
        " JOIN users u ON u.id = a.author_id ORDER BY a.pinned DESC, a.created_at DESC LIMIT 6"
    ).fetchall()
    open_tickets = db.execute(
        "SELECT COUNT(*) FROM tickets WHERE author_id = ? AND status IN ('open', 'in_progress')", (uid,)
    ).fetchone()[0]
    recent_tx = db.execute(
        "SELECT t.*, s.full_name AS sender_name, r.full_name AS recipient_name FROM transactions t"
        " LEFT JOIN users s ON s.id = t.sender_id JOIN users r ON r.id = t.recipient_id"
        " WHERE t.sender_id = ? OR t.recipient_id = ? ORDER BY t.id DESC LIMIT 5",
        (uid, uid),
    ).fetchall()
    clearances = allowed_clearances(level(g.user))
    doc_count = db.execute(
        f"SELECT COUNT(*) FROM documents WHERE clearance IN ({','.join('?' * len(clearances))})", clearances
    ).fetchone()[0]
    new_hires = db.execute(
        "SELECT id, full_name, title, department FROM users WHERE is_active = 1 AND role != 'contractor'"
        " ORDER BY hired_at DESC LIMIT 4"
    ).fetchall()
    return render_template(
        "dashboard.html",
        announcements=announcements,
        open_tickets=open_tickets,
        recent_tx=recent_tx,
        doc_count=doc_count,
        new_hires=new_hires,
    )

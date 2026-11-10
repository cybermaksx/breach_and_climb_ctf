from datetime import date

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

from .auth import EMAIL_RE, ROLE_LEVEL, revoke_sessions, roles_required
from .db import get_db
from .utils import money
from .wallet import WalletError, run_payroll

bp = Blueprint("admin", __name__, url_prefix="/admin")

MAX_SALARY = 100_000_000  # whole E Coin per year


@bp.route("/")
@roles_required("admin")
def index():
    db = get_db()
    stats = {
        "users": db.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0],
        "contractors": db.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'contractor' AND is_active = 1"
        ).fetchone()[0],
        "open_tickets": db.execute(
            "SELECT COUNT(*) FROM tickets WHERE status IN ('open', 'in_progress')"
        ).fetchone()[0],
        "documents": db.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
        "ec_supply": db.execute("SELECT COALESCE(SUM(balance), 0) FROM users").fetchone()[0],
    }
    recent_logins = db.execute(
        "SELECT id, full_name, role, last_login FROM users WHERE last_login IS NOT NULL"
        " ORDER BY last_login DESC LIMIT 8"
    ).fetchall()
    return render_template("admin/index.html", stats=stats, recent_logins=recent_logins)


@bp.route("/users")
@roles_required("admin")
def users():
    rows = get_db().execute(
        "SELECT u.*, m.full_name AS manager_name FROM users u LEFT JOIN users m ON m.id = u.manager_id"
        " ORDER BY u.is_active DESC, u.department, u.full_name"
    ).fetchall()
    return render_template("admin/users.html", users=rows)


@bp.route("/users/<int:user_id>", methods=("GET", "POST"))
@roles_required("admin")
def edit_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        abort(404)
    if request.method == "POST":
        f = request.form
        role = f.get("role", "")
        email = f.get("email", "").strip().lower()
        is_active = 1 if f.get("is_active") else 0
        try:
            salary = int(f.get("salary", "0"))
            manager_id = int(f["manager_id"]) if f.get("manager_id") else None
        except ValueError:
            salary, manager_id = -1, None
        if manager_id is not None and not db.execute("SELECT 1 FROM users WHERE id = ?", (manager_id,)).fetchone():
            manager_id = None
        if role not in ROLE_LEVEL or not EMAIL_RE.match(email) or not 0 <= salary <= MAX_SALARY:
            flash("Invalid role, email or salary.", "error")
        elif user_id == g.user["id"] and (role != "admin" or not is_active):
            flash("You cannot demote or disable your own account.", "error")
        elif manager_id == user_id:
            flash("A user cannot be their own manager.", "error")
        elif db.execute("SELECT 1 FROM users WHERE email = ? AND id != ?", (email, user_id)).fetchone():
            flash("Another account already uses that email.", "error")
        else:
            db.execute(
                "UPDATE users SET full_name = ?, email = ?, role = ?, department = ?, title = ?, salary = ?,"
                " manager_id = ?, is_active = ? WHERE id = ?",
                (
                    f.get("full_name", "").strip()[:80] or user["full_name"],
                    email,
                    role,
                    f.get("department", "").strip()[:60] or user["department"],
                    f.get("title", "").strip()[:100] or user["title"],
                    salary,
                    manager_id,
                    is_active,
                    user_id,
                ),
            )
            new_password = f.get("new_password", "")
            if new_password:
                if len(new_password) < 8:
                    flash("Password not changed: must be at least 8 characters.", "error")
                else:
                    db.execute(
                        "UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new_password), user_id)
                    )
                    revoke_sessions(db, user_id)
            if not is_active:
                revoke_sessions(db, user_id)
            db.commit()
            flash("User updated.", "success")
            return redirect(url_for("admin.edit_user", user_id=user_id))
    managers = db.execute(
        "SELECT id, full_name FROM users WHERE role IN ('manager', 'admin') AND id != ? ORDER BY full_name",
        (user_id,),
    ).fetchall()
    return render_template("admin/user_edit.html", user=user, managers=managers, roles=list(ROLE_LEVEL))


@bp.route("/announcements", methods=("GET", "POST"))
@roles_required("admin")
def announcements():
    db = get_db()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        if not title or not body:
            flash("Title and body are required.", "error")
        else:
            db.execute(
                "INSERT INTO announcements (author_id, title, body, pinned) VALUES (?, ?, ?, ?)",
                (g.user["id"], title[:200], body[:5000], 1 if request.form.get("pinned") else 0),
            )
            db.commit()
            flash("Announcement published.", "success")
            return redirect(url_for("admin.announcements"))
    items = db.execute(
        "SELECT a.*, u.full_name AS author_name FROM announcements a JOIN users u ON u.id = a.author_id"
        " ORDER BY a.created_at DESC"
    ).fetchall()
    return render_template("admin/announcements.html", items=items)


@bp.route("/announcements/<int:item_id>/delete", methods=("POST",))
@roles_required("admin")
def delete_announcement(item_id):
    db = get_db()
    db.execute("DELETE FROM announcements WHERE id = ?", (item_id,))
    db.commit()
    flash("Announcement removed.", "success")
    return redirect(url_for("admin.announcements"))


@bp.route("/payroll", methods=("GET", "POST"))
@roles_required("admin")
def payroll():
    db = get_db()
    if request.method == "POST":
        period = request.form.get("period", "").strip()
        try:
            count, total = run_payroll(db, period, g.user["id"])
            flash(f"Payroll {period}: paid {money(total)} EC to {count} employees.", "success")
        except WalletError as e:
            flash(str(e), "error")
        return redirect(url_for("admin.payroll"))
    runs = db.execute(
        "SELECT p.*, u.full_name AS run_by_name FROM payroll_runs p JOIN users u ON u.id = p.run_by"
        " ORDER BY p.period DESC"
    ).fetchall()
    monthly = db.execute(
        "SELECT COUNT(*), COALESCE(SUM(salary * 100 / 12), 0) FROM users"
        " WHERE is_active = 1 AND salary > 0 AND role != 'contractor'"
    ).fetchone()
    return render_template(
        "admin/payroll.html", runs=runs, monthly=monthly, current_period=date.today().strftime("%Y-%m")
    )

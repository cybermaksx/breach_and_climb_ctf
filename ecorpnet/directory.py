from flask import Blueprint, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .auth import login_required, revoke_sessions
from .db import get_db

bp = Blueprint("directory", __name__)

PUBLIC_COLUMNS = "id, username, full_name, email, title, department, phone, office, role"


@bp.route("/directory")
@login_required
def index():
    db = get_db()
    q = request.args.get("q", "").strip()
    department = request.args.get("department", "").strip()
    sql = f"SELECT {PUBLIC_COLUMNS} FROM users WHERE is_active = 1"
    params = []
    if q:
        sql += " AND (full_name LIKE ? OR username LIKE ? OR title LIKE ? OR email LIKE ?)"
        params += [f"%{q}%"] * 4
    if department:
        sql += " AND department = ?"
        params.append(department)
    sql += " ORDER BY department, full_name"
    people = db.execute(sql, params).fetchall()
    departments = [
        r[0] for r in db.execute("SELECT DISTINCT department FROM users WHERE is_active = 1 ORDER BY 1")
    ]
    return render_template(
        "directory/index.html", people=people, departments=departments, q=q, department=department
    )


@bp.route("/directory/<int:user_id>")
@login_required
def profile(user_id):
    db = get_db()
    person = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if person is None:
        abort(404)
    manager = None
    if person["manager_id"]:
        manager = db.execute(
            "SELECT id, full_name, title FROM users WHERE id = ?", (person["manager_id"],)
        ).fetchone()
    reports = db.execute(
        "SELECT id, full_name, title FROM users WHERE manager_id = ? AND is_active = 1 ORDER BY full_name",
        (user_id,),
    ).fetchall()
    can_see_comp = g.user["id"] == user_id or g.user["role"] == "admin"
    return render_template(
        "directory/profile.html", person=person, manager=manager, reports=reports, can_see_comp=can_see_comp
    )


@bp.route("/profile", methods=("GET", "POST"))
@login_required
def edit_profile():
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()[:40]
        office = request.form.get("office", "").strip()[:80]
        bio = request.form.get("bio", "").strip()[:1000]
        db = get_db()
        db.execute(
            "UPDATE users SET phone = ?, office = ?, bio = ? WHERE id = ?", (phone, office, bio, g.user["id"])
        )
        db.commit()
        flash("Profile updated.", "success")
        return redirect(url_for("directory.profile", user_id=g.user["id"]))
    return render_template("directory/edit.html")


@bp.route("/profile/password", methods=("POST",))
@login_required
def change_password():
    current = request.form.get("current", "")
    new = request.form.get("new", "")
    if not check_password_hash(g.user["password_hash"], current):
        flash("Current password is incorrect.", "error")
    elif len(new) < 8:
        flash("New password must be at least 8 characters.", "error")
    elif new != request.form.get("confirm", ""):
        flash("New passwords do not match.", "error")
    else:
        db = get_db()
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new), g.user["id"]))
        revoke_sessions(db, g.user["id"])
        db.commit()
        session["epoch"] = g.user["session_epoch"] + 1  # keep this browser signed in
        flash("Password changed.", "success")
    return redirect(url_for("directory.edit_profile"))

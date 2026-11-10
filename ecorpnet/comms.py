"""Admin bulk-email templates for E Corp notifications (welcome mails, E Coin notices...).

Contains the stage-2 CTF vulnerability: the "send test preview" feature renders
template bodies with the legacy Jinja mail engine (render_template_string, not
sandboxed), so Jinja expressions in a template body execute server-side
(SSTI -> arbitrary code execution, e.g. reverse shell).
"""
from flask import (
    Blueprint,
    abort,
    flash,
    g,
    redirect,
    render_template,
    render_template_string,
    request,
    url_for,
)
from jinja2.exceptions import TemplateError

from .auth import roles_required
from .db import get_db

bp = Blueprint("comms", __name__, url_prefix="/admin/comms")

# Placeholders available to template authors, pre-filled for previews.
SAMPLE = {
    "first_name": "Angela",
    "full_name": "Angela Moss",
    "department": "Risk Management",
    "title": "Risk Management Associate",
    "balance": "312.50",
    "ticket_id": 4172,
    "company": "E Corp",
}


def _get_template(tpl_id):
    tpl = get_db().execute("SELECT * FROM comms_templates WHERE id = ?", (tpl_id,)).fetchone()
    if tpl is None:
        abort(404)
    return tpl


@bp.route("/")
@roles_required("admin")
def index():
    items = get_db().execute(
        "SELECT t.*, u.full_name AS updated_by_name FROM comms_templates t"
        " JOIN users u ON u.id = t.updated_by ORDER BY t.name"
    ).fetchall()
    return render_template("admin/comms.html", items=items, sample=SAMPLE)


@bp.route("/", methods=("POST",))
@roles_required("admin")
def create():
    name = request.form.get("name", "").strip()
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "").strip()
    if not name or not subject or not body:
        flash("Name, subject and body are required.", "error")
    elif get_db().execute("SELECT 1 FROM comms_templates WHERE name = ?", (name,)).fetchone():
        flash("A template with that name already exists.", "error")
    else:
        db = get_db()
        cur = db.execute(
            "INSERT INTO comms_templates (name, subject, body, updated_by) VALUES (?, ?, ?, ?)",
            (name[:80], subject[:200], body[:10000], g.user["id"]),
        )
        db.commit()
        flash("Template created.", "success")
        return redirect(url_for("comms.edit", tpl_id=cur.lastrowid))
    return redirect(url_for("comms.index"))


@bp.route("/<int:tpl_id>", methods=("GET", "POST"))
@roles_required("admin")
def edit(tpl_id):
    tpl = _get_template(tpl_id)
    preview_body = preview_subject = None
    if request.method == "POST":
        db = get_db()
        button = request.form.get("button", "save")
        save_body = request.form.get("body", "").strip()
        if button == "preview":
            if not save_body:
                flash("Template body is empty.", "error")
            else:
                try:
                    # Intentional CTF vulnerability: previews go through the legacy
                    # Jinja mail engine (render_template_string, not sandboxed)
                    # instead of the queue's restricted pipeline.
                    preview_subject = render_template_string(request.form.get("subject", "").strip(), **SAMPLE)
                    preview_body = render_template_string(save_body, **SAMPLE)
                except TemplateError as e:
                    flash(f"Template rendering failed: {e.message!s}", "error")
        else:
            name = request.form.get("name", "").strip()
            subject = request.form.get("subject", "").strip()
            if not name or not subject or not save_body:
                flash("Name, subject and body are required.", "error")
            elif db.execute("SELECT 1 FROM comms_templates WHERE name = ? AND id != ?", (name, tpl_id)).fetchone():
                flash("A template with that name already exists.", "error")
            else:
                db.execute(
                    "UPDATE comms_templates SET name = ?, subject = ?, body = ?, updated_by = ?,"
                    " updated_at = datetime('now') WHERE id = ?",
                    (name[:80], subject[:200], save_body[:10000], g.user["id"], tpl_id),
                )
                db.commit()
                flash("Template saved.", "success")
                return redirect(url_for("comms.edit", tpl_id=tpl_id))
        tpl = dict(tpl)
        tpl.update({k: request.form.get(k, "").strip() for k in ("name", "subject", "body")})
    return render_template(
        "admin/comms_edit.html", tpl=tpl, sample=SAMPLE, preview_body=preview_body, preview_subject=preview_subject
    )


@bp.route("/<int:tpl_id>/delete", methods=("POST",))
@roles_required("admin")
def delete(tpl_id):
    db = get_db()
    db.execute("DELETE FROM comms_templates WHERE id = ?", (tpl_id,))
    db.commit()
    flash("Template removed.", "success")
    return redirect(url_for("comms.index"))

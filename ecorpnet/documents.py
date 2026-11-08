import os
import uuid

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from werkzeug.utils import secure_filename

from .auth import level, login_required, roles_required
from .db import get_db

bp = Blueprint("documents", __name__, url_prefix="/documents")

CLEARANCE_LEVEL = {"all": 0, "employee": 1, "manager": 2, "admin": 3}
CLEARANCE_LABELS = {
    "all": "All staff & contractors",
    "employee": "Employees only",
    "manager": "Management",
    "admin": "Executive / Admin",
}
CATEGORIES = ["Policy", "HR", "Finance", "IT", "Legal", "Executive"]
ALLOWED_EXTENSIONS = {"pdf", "txt", "md", "csv", "docx", "xlsx", "pptx", "png", "jpg", "jpeg"}
TEXT_EXTENSIONS = {"txt", "md", "csv"}


def allowed_clearances(user_level):
    return [k for k, v in CLEARANCE_LEVEL.items() if v <= user_level]


def extension(name):
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def get_document(doc_id):
    doc = get_db().execute(
        "SELECT d.*, u.full_name AS uploader_name FROM documents d JOIN users u ON u.id = d.uploaded_by"
        " WHERE d.id = ?",
        (doc_id,),
    ).fetchone()
    if doc is None:
        abort(404)
    if CLEARANCE_LEVEL[doc["clearance"]] > level(g.user):
        abort(403)
    return doc


@bp.app_context_processor
def inject_labels():
    return {"CLEARANCE_LABELS": CLEARANCE_LABELS}


@bp.route("/")
@login_required
def index():
    category = request.args.get("category", "")
    clearances = allowed_clearances(level(g.user))
    sql = (
        "SELECT d.*, u.full_name AS uploader_name FROM documents d JOIN users u ON u.id = d.uploaded_by"
        f" WHERE d.clearance IN ({','.join('?' * len(clearances))})"
    )
    params = list(clearances)
    if category in CATEGORIES:
        sql += " AND d.category = ?"
        params.append(category)
    sql += " ORDER BY d.category, d.title"
    docs = get_db().execute(sql, params).fetchall()
    return render_template("documents/index.html", docs=docs, category=category, CATEGORIES=CATEGORIES)


@bp.route("/<int:doc_id>")
@login_required
def view(doc_id):
    doc = get_document(doc_id)
    content = None
    if extension(doc["original_name"]) in TEXT_EXTENSIONS:
        path = os.path.join(current_app.config["DOCUMENTS_DIR"], doc["stored_name"])
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                content = f.read(200_000)
        except FileNotFoundError:
            abort(404)
    return render_template("documents/view.html", doc=doc, content=content)


@bp.route("/<int:doc_id>/download")
@login_required
def download(doc_id):
    doc = get_document(doc_id)
    return send_from_directory(
        current_app.config["DOCUMENTS_DIR"], doc["stored_name"], as_attachment=True, download_name=doc["original_name"]
    )


@bp.route("/upload", methods=("GET", "POST"))
@roles_required("manager", "admin")
def upload():
    form = request.form
    if request.method == "POST":
        file = request.files.get("file")
        title = form.get("title", "").strip()
        category = form.get("category", "")
        clearance = form.get("clearance", "")
        original = secure_filename(file.filename) if file and file.filename else ""
        ext = extension(original)
        if not file or not original:
            flash("Please choose a file.", "error")
        elif ext not in ALLOWED_EXTENSIONS:
            flash(f"File type .{ext} is not allowed.", "error")
        elif not title or category not in CATEGORIES or clearance not in CLEARANCE_LEVEL:
            flash("Title, category and clearance are required.", "error")
        elif CLEARANCE_LEVEL[clearance] > level(g.user):
            flash("You cannot publish above your own clearance.", "error")
        else:
            stored = f"{uuid.uuid4().hex}.{ext}"
            path = os.path.join(current_app.config["DOCUMENTS_DIR"], stored)
            file.save(path)
            db = get_db()
            cur = db.execute(
                "INSERT INTO documents (title, description, category, clearance, stored_name, original_name,"
                " size, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    title[:200],
                    form.get("description", "").strip()[:1000],
                    category,
                    clearance,
                    stored,
                    original,
                    os.path.getsize(path),
                    g.user["id"],
                ),
            )
            db.commit()
            flash("Document published.", "success")
            return redirect(url_for("documents.view", doc_id=cur.lastrowid))
    allowed = allowed_clearances(level(g.user))
    return render_template("documents/upload.html", form=form, CATEGORIES=CATEGORIES, allowed=allowed)


@bp.route("/<int:doc_id>/delete", methods=("POST",))
@login_required
def delete(doc_id):
    doc = get_document(doc_id)
    if g.user["role"] != "admin" and doc["uploaded_by"] != g.user["id"]:
        abort(403)
    db = get_db()
    db.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    db.commit()
    try:
        os.remove(os.path.join(current_app.config["DOCUMENTS_DIR"], doc["stored_name"]))
    except FileNotFoundError:
        pass
    flash("Document deleted.", "success")
    return redirect(url_for("documents.index"))

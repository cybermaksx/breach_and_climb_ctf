import csv
import io
from datetime import date

from flask import Blueprint, Response, abort, flash, g, redirect, render_template, request, url_for

from .auth import roles_required
from .db import get_db
from .utils import money

bp = Blueprint("reports", __name__, url_prefix="/reports")

REPORT_TYPES = {
    "headcount": "Headcount by department",
    "tickets": "IT ticket summary",
    "payroll": "Payroll & compensation",
    "wallet": "E Coin activity",
}
TICKET_STATUSES = ["open", "in_progress", "resolved", "closed"]


def _valid_date(value):
    try:
        return date.fromisoformat(value).isoformat()
    except (TypeError, ValueError):
        return None


def _csv_safe(value):
    """Neutralise spreadsheet formulas (=, +, -, @) in exported cells."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def get_report(report_id):
    report = get_db().execute(
        "SELECT r.*, u.full_name AS author_name FROM reports r JOIN users u ON u.id = r.author_id WHERE r.id = ?",
        (report_id,),
    ).fetchone()
    if report is None:
        abort(404)
    if report["author_id"] != g.user["id"] and g.user["role"] != "admin":
        abort(403)
    return report


# All users reporting (directly or indirectly) to ? plus that user. UNION (not UNION ALL) stops on cycles.
TEAM_CTE = (
    "WITH RECURSIVE team(id) AS (SELECT ? UNION SELECT u.id FROM users u JOIN team t ON u.manager_id = t.id) "
)


def build_report(report):
    """Return {'columns': [...], 'rows': [[...]], 'summary': [(label, value)]} for a saved report.

    Reports created by managers carry scope_user_id: compensation data (payroll, E Coin) is then
    limited to that manager's own reporting chain, so nobody sees the pay of peers or superiors.
    """
    db = get_db()
    scope = report["scope_user_id"]
    dept = report["department"]
    d_from, d_to = report["date_from"], report["date_to"]
    kind = report["report_type"]

    if kind == "headcount":
        sql = (
            "SELECT department, COUNT(*), SUM(role = 'manager'), SUM(role = 'contractor'), MIN(hired_at)"
            " FROM users WHERE is_active = 1"
        )
        params = []
        if dept:
            sql += " AND department = ?"
            params.append(dept)
        rows = [list(r) for r in db.execute(sql + " GROUP BY department ORDER BY department", params)]
        return {
            "columns": ["Department", "Headcount", "Managers", "Contractors", "Earliest hire"],
            "rows": rows,
            "summary": [("Total headcount", sum(r[1] for r in rows)), ("Departments", len(rows))],
        }

    if kind == "tickets":
        sql = (
            "SELECT t.category, t.status, COUNT(*) FROM tickets t JOIN users u ON u.id = t.author_id"
            " WHERE date(t.created_at) BETWEEN ? AND ?"
        )
        params = [d_from, d_to]
        if dept:
            sql += " AND u.department = ?"
            params.append(dept)
        pivot = {}
        for category, status, count in db.execute(sql + " GROUP BY t.category, t.status", params):
            pivot.setdefault(category, dict.fromkeys(TICKET_STATUSES, 0))[status] = count
        rows = [[c, *(v[s] for s in TICKET_STATUSES), sum(v.values())] for c, v in sorted(pivot.items())]
        total = sum(r[-1] for r in rows)
        unresolved = sum(r[1] + r[2] for r in rows)
        return {
            "columns": ["Category", "Open", "In progress", "Resolved", "Closed", "Total"],
            "rows": rows,
            "summary": [("Tickets", total), ("Unresolved", unresolved)],
        }

    if kind == "payroll":
        sql = (
            (TEAM_CTE if scope else "")
            + "SELECT u.full_name, u.title, u.department, u.salary,"
            " COALESCE((SELECT SUM(amount) FROM transactions t WHERE t.recipient_id = u.id AND t.kind = 'payroll'"
            "  AND date(t.created_at) BETWEEN ? AND ?), 0)"
            " FROM users u WHERE u.is_active = 1 AND u.role != 'contractor'"
        )
        params = [scope] if scope else []
        params += [d_from, d_to]
        if scope:
            sql += " AND u.id IN (SELECT id FROM team)"
        if dept:
            sql += " AND u.department = ?"
            params.append(dept)
        raw = db.execute(sql + " ORDER BY u.department, u.salary DESC", params).fetchall()
        rows = [[r[0], r[1], r[2], f"{r[3]:,}", money(r[4])] for r in raw]
        return {
            "columns": ["Employee", "Title", "Department", "Annual salary (EC)", "Paid in period (EC)"],
            "rows": rows,
            "summary": [
                ("Employees", len(raw)),
                ("Annual payroll (EC)", f"{sum(r[3] for r in raw):,}"),
                ("Paid in period (EC)", money(sum(r[4] for r in raw))),
            ],
        }

    if kind == "wallet":
        sql = (
            (TEAM_CTE if scope else "")
            + "SELECT t.kind, COUNT(*), SUM(t.amount), MAX(t.amount) FROM transactions t"
            " JOIN users u ON u.id = t.recipient_id WHERE date(t.created_at) BETWEEN ? AND ?"
        )
        params = [scope] if scope else []
        params += [d_from, d_to]
        if scope:
            sql += " AND u.id IN (SELECT id FROM team)"
        if dept:
            sql += " AND u.department = ?"
            params.append(dept)
        raw = db.execute(sql + " GROUP BY t.kind ORDER BY t.kind", params).fetchall()
        rows = [[r[0], r[1], money(r[2]), money(r[3])] for r in raw]
        return {
            "columns": ["Type", "Transactions", "Volume (EC)", "Largest (EC)"],
            "rows": rows,
            "summary": [("Transactions", sum(r[1] for r in raw)), ("Volume (EC)", money(sum(r[2] for r in raw)))],
        }

    abort(400)


@bp.route("/")
@roles_required("manager", "admin")
def index():
    db = get_db()
    if g.user["role"] == "admin":
        saved = db.execute(
            "SELECT r.*, u.full_name AS author_name FROM reports r JOIN users u ON u.id = r.author_id"
            " ORDER BY r.id DESC"
        ).fetchall()
    else:
        saved = db.execute(
            "SELECT r.*, u.full_name AS author_name FROM reports r JOIN users u ON u.id = r.author_id"
            " WHERE r.author_id = ? ORDER BY r.id DESC",
            (g.user["id"],),
        ).fetchall()
    departments = [r[0] for r in db.execute("SELECT DISTINCT department FROM users ORDER BY 1")]
    today = date.today()
    return render_template(
        "reports/index.html",
        saved=saved,
        departments=departments,
        REPORT_TYPES=REPORT_TYPES,
        default_from=today.replace(month=1, day=1).isoformat(),
        default_to=today.isoformat(),
    )


@bp.route("/", methods=("POST",))
@roles_required("manager", "admin")
def create():
    form = request.form
    title = form.get("title", "").strip()
    report_type = form.get("report_type", "")
    d_from, d_to = _valid_date(form.get("date_from")), _valid_date(form.get("date_to"))
    # Managers only report on their own department; admins may choose any (or all).
    department = form.get("department", "").strip() if g.user["role"] == "admin" else g.user["department"]
    if not title or report_type not in REPORT_TYPES:
        flash("Title and report type are required.", "error")
    elif not d_from or not d_to or d_from > d_to:
        flash("Please choose a valid date range.", "error")
    else:
        db = get_db()
        cur = db.execute(
            "INSERT INTO reports (author_id, title, report_type, department, date_from, date_to, notes,"
            " scope_user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                g.user["id"],
                title[:120],
                report_type,
                department,
                d_from,
                d_to,
                form.get("notes", "").strip()[:2000],
                None if g.user["role"] == "admin" else g.user["id"],
            ),
        )
        db.commit()
        return redirect(url_for("reports.view", report_id=cur.lastrowid))
    return redirect(url_for("reports.index"))


@bp.route("/<int:report_id>")
@roles_required("manager", "admin")
def view(report_id):
    report = get_report(report_id)
    return render_template("reports/view.html", report=report, data=build_report(report), REPORT_TYPES=REPORT_TYPES)


@bp.route("/<int:report_id>/export.csv")
@roles_required("manager", "admin")
def export(report_id):
    report = get_report(report_id)
    data = build_report(report)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([_csv_safe(report["title"])])
    writer.writerow([f"{REPORT_TYPES[report['report_type']]} | {report['date_from']} - {report['date_to']}"])
    writer.writerow([])
    writer.writerow(data["columns"])
    writer.writerows([[_csv_safe(c) for c in row] for row in data["rows"]])
    filename = f"ecorp_report_{report_id}.csv"
    return Response(
        buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@bp.route("/<int:report_id>/delete", methods=("POST",))
@roles_required("manager", "admin")
def delete(report_id):
    get_report(report_id)
    db = get_db()
    db.execute("DELETE FROM reports WHERE id = ?", (report_id,))
    db.commit()
    flash("Report deleted.", "success")
    return redirect(url_for("reports.index"))

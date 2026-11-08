import re
import sqlite3
from datetime import date

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from .auth import login_required
from .db import get_db
from .utils import parse_amount

bp = Blueprint("wallet", __name__, url_prefix="/wallet")

PERIOD_RE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")


class WalletError(Exception):
    pass


def transfer(db, sender_id, recipient_id, cents, memo="", kind="transfer"):
    if sender_id == recipient_id:
        raise WalletError("You cannot send E Coin to yourself.")
    cur = db.execute(
        "UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?", (cents, sender_id, cents)
    )
    if cur.rowcount != 1:
        db.rollback()
        raise WalletError("Insufficient E Coin balance.")
    db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (cents, recipient_id))
    db.execute(
        "INSERT INTO transactions (sender_id, recipient_id, amount, kind, memo) VALUES (?, ?, ?, ?, ?)",
        (sender_id, recipient_id, cents, kind, memo[:140]),
    )
    db.commit()


def run_payroll(db, period, run_by):
    """Pay one month of salary (annual / 12) from the treasury to every active salaried employee."""
    if not PERIOD_RE.match(period):
        raise WalletError("Period must be in YYYY-MM format.")
    if period > date.today().strftime("%Y-%m"):
        raise WalletError("Payroll cannot be run for a future period.")
    try:
        cur = db.execute(
            "INSERT INTO payroll_runs (period, run_by, employees, total) VALUES (?, ?, 0, 0)", (period, run_by)
        )
    except sqlite3.IntegrityError:
        db.rollback()
        raise WalletError(f"Payroll for {period} has already been processed.")
    run_id = cur.lastrowid
    staff = db.execute(
        "SELECT id, salary FROM users WHERE is_active = 1 AND salary > 0 AND role != 'contractor'"
    ).fetchall()
    total = 0
    for person in staff:
        cents = person["salary"] * 100 // 12
        total += cents
        db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (cents, person["id"]))
        db.execute(
            "INSERT INTO transactions (sender_id, recipient_id, amount, kind, memo)"
            " VALUES (NULL, ?, ?, 'payroll', ?)",
            (person["id"], cents, f"Salary {period}"),
        )
    db.execute("UPDATE payroll_runs SET employees = ?, total = ? WHERE id = ?", (len(staff), total, run_id))
    db.commit()
    return len(staff), total


@bp.route("/")
@login_required
def index():
    db = get_db()
    uid = g.user["id"]
    kind = request.args.get("kind", "")
    sql = (
        "SELECT t.*, s.full_name AS sender_name, r.full_name AS recipient_name FROM transactions t"
        " LEFT JOIN users s ON s.id = t.sender_id JOIN users r ON r.id = t.recipient_id"
        " WHERE (t.sender_id = ? OR t.recipient_id = ?)"
    )
    params = [uid, uid]
    if kind in ("transfer", "payroll", "bonus"):
        sql += " AND t.kind = ?"
        params.append(kind)
    sql += " ORDER BY t.id DESC LIMIT 100"
    history = db.execute(sql, params).fetchall()
    stats = db.execute(
        "SELECT COALESCE(SUM(CASE WHEN recipient_id = ? THEN amount END), 0) AS received,"
        " COALESCE(SUM(CASE WHEN sender_id = ? THEN amount END), 0) AS sent"
        " FROM transactions WHERE sender_id = ? OR recipient_id = ?",
        (uid, uid, uid, uid),
    ).fetchone()
    colleagues = db.execute(
        "SELECT username, full_name FROM users WHERE is_active = 1 AND id != ? ORDER BY full_name", (uid,)
    ).fetchall()
    return render_template("wallet/index.html", history=history, stats=stats, colleagues=colleagues, kind=kind)


@bp.route("/transfer", methods=("POST",))
@login_required
def send():
    db = get_db()
    username = request.form.get("recipient", "").strip().lower()
    cents = parse_amount(request.form.get("amount"))
    memo = request.form.get("memo", "").strip()
    recipient = db.execute(
        "SELECT id, full_name FROM users WHERE username = ? AND is_active = 1", (username,)
    ).fetchone()
    if recipient is None:
        flash("Recipient not found.", "error")
    elif cents is None:
        flash("Enter a valid positive amount (max 2 decimals).", "error")
    else:
        try:
            transfer(db, g.user["id"], recipient["id"], cents, memo)
            flash(f"Sent {cents / 100:,.2f} EC to {recipient['full_name']}.", "success")
        except WalletError as e:
            flash(str(e), "error")
    return redirect(url_for("wallet.index"))

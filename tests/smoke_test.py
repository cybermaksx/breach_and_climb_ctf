"""Functional smoke test: every page and main workflow for each role.

Run: python3 tests/smoke_test.py
"""
import io
import re
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from ecorpnet import create_app  # noqa: E402
from ecorpnet.db import get_db, init_db  # noqa: E402
from ecorpnet.seed import seed  # noqa: E402

# Isolated throw-away database and documents dir: the real instance/ data is never touched.
_tmp = tempfile.mkdtemp(prefix="ecorpnet-test-")
app = create_app({"DATABASE": os.path.join(_tmp, "test.db"), "DOCUMENTS_DIR": os.path.join(_tmp, "documents")})
with app.app_context():
    init_db()
    seed(get_db(), app.config["DOCUMENTS_DIR"])
fails = []
def csrf(c):
    with c.session_transaction() as s:
        s.setdefault("_csrf", "t"); return s["_csrf"]
def login(c, u, p):
    tok = csrf(c)
    r = c.post("/login", data={"username": u, "password": p, "csrf_token": tok})
    assert r.status_code == 302, (u, r.status_code); c.get("/")
def get(c, url, expect=200):
    r = c.get(url)
    if r.status_code != expect: fails.append((url, r.status_code, expect))
    return r
def post(c, url, data, expect=302):
    with c.session_transaction() as s: data["csrf_token"] = s.get("_csrf","x")
    r = c.post(url, data=data)
    if r.status_code != expect: fails.append(("POST "+url, r.status_code, expect, r.data[:300]))
    return r

pages = ["/", "/directory", "/directory/1", "/directory?q=tyrell", "/profile", "/tickets/", "/tickets/new",
         "/documents/", "/wallet/", "/api/v1/", "/api/v1/me", "/api/v1/employees", "/api/v1/employees/2", "/api/v1/wallet", "/api/v1/tickets"]

# admin
c = app.test_client(); login(c, "pprice", "Pr1ce-0f-P0wer#1987")
for p in pages + ["/reports/", "/admin/", "/admin/users", "/admin/users/9", "/admin/announcements", "/admin/payroll", "/tickets/1", "/documents/5"]:
    get(c, p)
for t in ["headcount", "tickets", "payroll", "wallet"]:
    r = post(c, "/reports/", {"title": "T "+t, "report_type": t, "date_from": "2000-01-01", "date_to": "2030-01-01", "department": "", "notes": "{{7*7}} <b>x</b>"})
    loc = r.headers["Location"]; rr = get(c, loc); get(c, loc + "/export.csv")
    assert b"{{7*7}}" in rr.data and b"&lt;b&gt;" in rr.data
post(c, "/admin/payroll", {"period": "2026-11"})
post(c, "/admin/announcements", {"title": "Hello", "body": "World"})
post(c, "/admin/users/9", {"full_name": "Angela Moss", "email": "amoss@e-corp.com", "role": "employee", "department": "Risk Management", "title": "Risk Management Associate", "salary": "75000", "manager_id": "8", "is_active": "on"})
post(c, "/tickets/2/update", {"status": "in_progress", "priority": "high", "assignee_id": "5"})
# upload
with c.session_transaction() as s: tok = s["_csrf"]
r = c.post("/documents/upload", data={"csrf_token": tok, "title": "Test", "category": "IT", "clearance": "all", "file": (io.BytesIO(b"hello"), "test.txt")}, content_type="multipart/form-data")
assert r.status_code == 302, r.data[:300]
get(c, r.headers["Location"])

# contractor registration
c2 = app.test_client(); tok = csrf(c2)
r = c2.post("/register", data={"csrf_token": tok, "username": "elliot", "full_name": "Elliot Alderson", "email": "elliot@allsafe.com", "company": "Allsafe", "password": "password123", "confirm": "password123"})
assert r.status_code == 302
login(c2, "elliot", "password123")
for p in pages: get(c2, p)
get(c2, "/reports/", 403); get(c2, "/admin/", 403); get(c2, "/tickets/1", 403); get(c2, "/documents/5", 403); get(c2, "/documents/upload", 403)
r = post(c2, "/tickets/new", {"subject": "hi", "category": "Other", "priority": "low", "body": "test"})
tid = r.headers["Location"].rsplit("/",1)[1]
post(c2, f"/tickets/{tid}/comment", {"body": "more"})
post(c2, "/wallet/transfer", {"recipient": "amoss", "amount": "5", "memo": "x"})  # insufficient -> flash
# employee transfer
c3 = app.test_client(); login(c3, "amoss", "Wash1ngton-Twp-1993")
post(c3, "/wallet/transfer", {"recipient": "elliot", "amount": "12.50", "memo": "welcome"})
r = c3.get("/wallet/"); assert "−12.50".encode() in r.data
get(c3, "/reports/", 403)
# manager
c4 = app.test_client(); login(c4, "twellick", "Joanna&Me-Forever09")
get(c4, "/reports/"); get(c4, "/documents/4"); get(c4, "/documents/5", 403)
r = post(c4, "/reports/", {"title": "x", "report_type": "payroll", "date_from": "2000-01-01", "date_to": "2030-01-01", "department": "Finance"})
rr = get(c4, r.headers["Location"]); assert b"Lucy Chen" not in rr.data and b"Terry Colby" in rr.data
# it staff
c5 = app.test_client(); login(c5, "pnair", "Nair-Sysadm1n-NOC!")
get(c5, "/tickets/1"); get(c5, f"/tickets/{tid}")
# bad csrf, 404, unauth
c6 = app.test_client()
get(c6, "/", 302); get(c6, "/nope", 404); get(c6, "/api/v1/me", 401)
r = c6.post("/login", data={"username": "a", "password": "b"}); assert r.status_code == 400
print("FAILS:", fails or "none")
sys.exit(1 if fails else 0)

"""Security regression checks for the clean (non-vulnerable) ECorpNet build.

Every line must print OK. When CTF vulnerabilities are added on purpose,
update the matching checks so only the intended holes are open.

Run: python3 tests/security_test.py
"""
import io
import itertools
import re
import stat
import threading
import time
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
app.config["PROPAGATE_EXCEPTIONS"] = False
R = []
_ip = itertools.count(1)
def new_client():
    """Test client with its own source IP (rate limits are per IP)."""
    n = next(_ip)
    c = app.test_client()
    c.environ_base["REMOTE_ADDR"] = f"10.{n // 65536}.{n // 256 % 256}.{n % 256}"
    return c
def check(name, ok, info=""):
    R.append((("OK  " if ok else "VULN"), name, info))
def client(u=None, p=None):
    c = new_client()
    if u:
        with c.session_transaction() as s: s["_csrf"] = "t"
        r = c.post("/login", data={"username": u, "password": p, "csrf_token": "t"}); assert r.status_code == 302
        c.get("/wallet/")
    return c
def tok(c):
    with c.session_transaction() as s: return s.get("_csrf", "")
def post(c, url, data, **kw):
    data = dict(data); data.setdefault("csrf_token", tok(c)); return c.post(url, data=data, **kw)

admin = client("pprice", "bowwow")
emp = client("amoss", "Wash1ngton-Twp-1993")
mgr = client("twellick", "Joanna&Me-Forever09")
anon = new_client()
# contractor with XSS / formula name
with anon.session_transaction() as s: s["_csrf"] = "t"
xss = '<script>alert(1)</script>"><img src=x onerror=alert(1)>'
post(anon, "/register", {"username": "evil", "full_name": "=HYPERLINK(\"http://x\")" , "email": "e@x.io", "company": xss, "password": "password123", "confirm": "password123"})
con = client("evil", "password123")

# --- auth / session
r = anon.get("/login?next=x"); 
for nxt in ["//evil.com", "/\\evil.com", "/\t/evil.com", "https://evil.com"]:
    c = new_client()
    with c.session_transaction() as s: s["_csrf"] = "t"
    r = c.post("/login?next=" + nxt, data={"username": "evil", "password": "password123", "csrf_token": "t"})
    loc = r.headers.get("Location", "")
    check(f"open redirect next={nxt!r}", "evil" not in loc, loc)
r = post(anon, "/login", {"username": "pprice' OR '1'='1", "password": "x' OR '1'='1"}); check("SQLi login", r.status_code == 200 and b"Invalid" in r.data)
check("mass assignment profile role", (post(con, "/profile", {"phone": "1", "role": "admin", "salary": "999"}), con.get("/admin/").status_code == 403)[1])
r = con.post("/wallet/transfer", data={"recipient": "amoss", "amount": "1"}); check("CSRF without token", r.status_code == 400)
r = con.get("/logout"); check("logout via GET (CSRF-able logout)", r.status_code == 405, r.status_code)
r = post(con, "/logout", {}); check("logout via POST works", r.status_code == 302 and con.get("/").status_code == 302)
con = client("evil", "password123")
# stolen cookie survives logout?
c = client("evil", "password123"); cookie = c.get_cookie("session").value
post(c, "/logout", {}); c2 = new_client(); c2.set_cookie("session", cookie)
check("old session cookie after logout/pw change revoked", c2.get("/").status_code == 302, "stateless cookie still valid" )
con = client("evil", "password123")
# brute force
c = new_client()
with c.session_transaction() as s: s["_csrf"] = "t"
codes = [c.post("/login", data={"username": "amoss", "password": f"x{i}", "csrf_token": "t"}).status_code for i in range(30)]
check("login brute-force rate limit", 429 in codes, f"30 attempts → {set(codes)}")
# timing user enumeration
t=time.time(); [post(anon,"/login",{"username":"nouser","password":"x"}) for _ in range(5)]; a=time.time()-t
t=time.time(); [post(anon,"/login",{"username":"rstone","password":"x"}) for _ in range(5)]; b=time.time()-t
check("login timing user enumeration", b < a*3, f"nouser {a:.3f}s vs real {b:.3f}s")

a1 = client("ogrant", "Spreadsh33t-Kn1ght"); a2 = client("ogrant", "Spreadsh33t-Kn1ght")
post(a1, "/profile/password", {"current": "Spreadsh33t-Kn1ght", "new": "NewPassw0rd!", "confirm": "NewPassw0rd!"})
check("pw change keeps current session", a1.get("/").status_code == 200)
check("pw change kills other sessions", a2.get("/").status_code == 302)
# disabled user is kicked out
v = client("mwebb", "Onb0arding-Day-1!")
post(admin, "/admin/users/11", {"full_name":"Marcus Webb","email":"mwebb@e-corp.com","role":"employee","department":"Human Resources","title":"HR Generalist","salary":"68000"})
check("disabled user kicked out", v.get("/").status_code == 302)
check("CSP blocks inline script", "script-src 'self'" in emp.get("/").headers.get("Content-Security-Policy",""))
r = emp.get("/documents/1"); check("no inline JS in pages", b"onsubmit=" not in r.data and b"onclick=" not in r.data)
# --- headers
r = emp.get("/wallet/")
check("X-Frame-Options (clickjacking)", "X-Frame-Options" in r.headers or "frame-ancestors" in r.headers.get("Content-Security-Policy",""))
check("X-Content-Type-Options", r.headers.get("X-Content-Type-Options") == "nosniff")
sc = [h for h in emp.get("/").headers.getlist("Set-Cookie")] 
c = new_client()
with c.session_transaction() as s: s["_csrf"]="t"
r = c.post("/login", data={"username":"amoss","password":"Wash1ngton-Twp-1993","csrf_token":"t"})
setc = r.headers.get("Set-Cookie","")
check("cookie HttpOnly", "HttpOnly" in setc); check("cookie SameSite", "SameSite" in setc, setc[-60:])

# --- XSS
for url in ["/directory?q=evil", "/admin/users"]:
    r = admin.get(url); check(f"stored XSS {url}", b"<script>alert(1)" not in r.data and b"<img src=x" not in r.data)
r = admin.get("/directory?q=<script>x</script>"); check("reflected XSS search", b"<script>x" not in r.data)
post(con, "/tickets/new", {"subject": xss, "category": "Other", "priority": "low", "body": xss})
r = admin.get("/tickets/"); check("stored XSS tickets", b"<script>alert(1)" not in r.data)

# --- SQLi probes
for url in ["/directory?q=%27%20OR%201=1--", "/directory?department=%27%20OR%201=1--", "/api/v1/employees?q=%27)--", "/tickets/?status=%27--", "/wallet/?kind=%27--", "/documents/?category=%27--"]:
    r = emp.get(url); check(f"SQLi {url}", r.status_code in (200,) and b"Traceback" not in r.data, r.status_code)

# --- access control / IDOR
check("contractor -> others ticket", con.get("/tickets/1").status_code == 403)
check("contractor -> admin doc", con.get("/documents/5").status_code == 403)
check("contractor -> admin doc download", con.get("/documents/5/download").status_code == 403)
check("employee -> manager doc", emp.get("/documents/4/download").status_code == 403)
check("employee -> ticket update (staff only)", post(emp, "/tickets/2/update", {"status":"closed","priority":"low"}).status_code == 403)
check("employee -> close others ticket", post(emp, "/tickets/1/close", {}).status_code == 403)
check("employee -> reports", emp.get("/reports/").status_code == 403)
check("manager -> admin", mgr.get("/admin/users").status_code == 403)
check("manager -> doc delete not own", post(mgr, "/documents/1/delete", {}).status_code == 403)
admin_rep = post(admin, "/reports/", {"title":"a","report_type":"payroll","date_from":"2000-01-01","date_to":"2030-01-01","department":""}).headers["Location"]
check("manager -> admin report IDOR", mgr.get(admin_rep).status_code == 403)
check("manager -> admin report CSV", mgr.get(admin_rep + "/export.csv").status_code == 403)

# --- comms templates (stage-2 CTF: SSTI via render_template_string is intentionally open for admins only)
check("contractor -> comms templates", con.get("/admin/comms/").status_code in (302, 403), f"login redirect/403")
check("employee -> comms templates", emp.get("/admin/comms/").status_code in (302, 403))
check("manager -> comms templates", mgr.get("/admin/comms/").status_code == 403)
check("anon -> comms templates", new_client().get("/admin/comms/").status_code == 302)
r = post(admin, "/admin/comms/1", {"name": "welcome_new_hire", "subject": "s", "body": "{{ 26 * 255 }}", "button": "preview"})
check("comms preview SSTI renders for admin (intended hole)", r.status_code == 200 and b"6630" in r.data, r.status_code)
r = post(admin, "/admin/comms/", {"title": "x", "body": "{{ 26 * 255 }}", "pinned": "1"})
dash = emp.get("/")
check("SSTI does NOT render outside comms preview", b"6630" not in dash.data, r.status_code)
r = post(admin, "/admin/comms/1", {"name": "welcome_new_hire", "subject": "{{ bad<body", "body": "{% for x in %}", "button": "preview"})
check("comms preview template error → no 500", r.status_code == 200, r.status_code)
r = post(mgr, "/reports/", {"title":"b","report_type":"payroll","date_from":"2000-01-01","date_to":"2030-01-01","department":"Executive"})
check("manager -> other dept payroll", b"Phillip Price" not in mgr.get(r.headers["Location"]).data)
r = emp.get("/directory/1"); check("employee sees CEO salary", b"1,200,000" not in r.data)
r = emp.get("/api/v1/employees/1"); check("API leaks salary/hash", b"salary" not in r.data and b"password" not in r.data and b"balance" not in r.data)
check("API unauth", anon.get("/api/v1/employees").status_code == 401)

# --- uploads
def up(c, name, data=b"x", clearance="all"):
    return post(c, "/documents/upload", {"title":"t","category":"IT","clearance":clearance,"file":(io.BytesIO(data), name)}, content_type="multipart/form-data")
r = up(mgr, "shell.html"); check("upload .html", r.status_code == 200 and b"not allowed" in r.data)
r = up(mgr, "../../../tmp/pwn.txt"); loc = r.headers.get("Location")
check("upload path traversal", not os.path.exists("/tmp/pwn.txt"))
r = up(mgr, "x.txt", clearance="admin"); check("manager uploads above clearance", b"cannot publish" in r.data)
r = up(con, "x.txt"); check("contractor upload", r.status_code == 403)
r = mgr.get(loc.replace("", "") + "/download") if loc else None
if r: check("download Content-Disposition attachment", "attachment" in r.headers.get("Content-Disposition",""))

# --- wallet logic
def bal(c): return int(c.get("/api/v1/me").json["balance"]*100)
b0 = bal(emp)
for amt in ["-100", "0", "0.001", "1e9999", "NaN", "Infinity", "abc", "99999999999"]:
    post(emp, "/wallet/transfer", {"recipient":"ogrant","amount":amt})
check("wallet bad amounts rejected", bal(emp) == b0)
post(emp, "/wallet/transfer", {"recipient":"amoss","amount":"10"}); check("self transfer", bal(emp)==b0)
post(emp, "/wallet/transfer", {"recipient":"ogrant","amount":str(b0/100 + 1)}); check("overdraft", bal(emp)==b0)
# race: 20 parallel transfers of full balance from contractor-funded account
post(emp, "/wallet/transfer", {"recipient":"evil","amount":"10"})
cb = bal(con)
def go():
    c = client("evil", "password123"); post(c, "/wallet/transfer", {"recipient":"ogrant","amount":"10"})
ths = [threading.Thread(target=go) for _ in range(15)]; [t.start() for t in ths]; [t.join() for t in ths]
check("race condition double spend", bal(con) >= 0, f"balance after race {bal(con)}")

# --- robustness (500s)
r = post(admin, "/admin/users/9", {"full_name":"A","email":"pprice@e-corp.com","role":"employee","department":"x","title":"x","salary":"1"})
check("admin dup email → no 500", r.status_code != 500, r.status_code)
r = post(admin, "/admin/users/9", {"full_name":"A","email":"amoss@e-corp.com","role":"employee","department":"x","title":"x","salary":"1","manager_id":"abc"}); check("admin bad manager_id", r.status_code != 500, r.status_code)
r = post(admin, "/admin/payroll", {"period":"2099-12"}); check("payroll far future period", b"2099-12" not in admin.get("/admin/payroll").data)
r = post(admin, "/tickets/1/update", {"status":"open","priority":"low","assignee_id":"abc"}); check("ticket bad assignee", r.status_code == 400, r.status_code)
r = post(admin, "/reports/", {"title":"x","report_type":"tickets","date_from":"2020-13-45","date_to":"x"}); check("report bad dates", r.status_code == 302)
# csv injection
r = post(admin, "/reports/", {"title":"=cmd|' /C calc'!A0","report_type":"headcount","date_from":"2000-01-01","date_to":"2030-01-01","department":""})
csvd = admin.get(r.headers["Location"] + "/export.csv").data
check("CSV formula injection", not re.search(rb"(^|\n|,)=cmd", csvd), csvd[:40])
# file perms
for f in [os.path.join(app.instance_path, "secret_key"), app.config["DATABASE"]]:
    m = stat.S_IMODE(os.stat(f).st_mode)
    check(f"{os.path.basename(f)} not world-readable", not (m & 0o044), oct(m))
m = stat.S_IMODE(os.stat(app.instance_path).st_mode)
check("instance dir private", not (m & 0o077), oct(m))
# missing doc file
import sqlite3; d = sqlite3.connect(app.config["DATABASE"]); sn = d.execute("select stored_name from documents where id=1").fetchone()[0]
p = os.path.join(app.config["DOCUMENTS_DIR"], sn); os.rename(p, p+".bak")
r = emp.get("/documents/1"); check("missing file → no 500", r.status_code != 500, r.status_code); os.rename(p+".bak", p)


# =====================================================================
# Review #2
# =====================================================================
def fresh_ip_client():
    c = new_client()
    with c.session_transaction() as s: s["_csrf"] = "t"
    return c
USERS = ["pprice", "tcolby", "twellick", "sknowles", "pnair", "dlin", "kdoyle", "rhale", "amoss", "hcole",
         "mwebb", "lchen", "ogrant", "rstone", "jkim"]

# password spraying: one IP, one password per user, many users
c = fresh_ip_client()
codes = [c.post("/login", data={"username": u, "password": pw, "csrf_token": "t"}).status_code
         for pw in ["Password1", "Summer2015!", "Ecorp123!", "Welcome1"] for u in USERS]
check("password spraying limited per IP", 429 in codes, {x: codes.count(x) for x in set(codes)})
# blocked IP cannot log in even with the right password; another IP can
r = c.post("/login", data={"username": "amoss", "password": "Wash1ngton-Twp-1993", "csrf_token": "t"})
check("blocked IP stays blocked with valid password", r.status_code == 429)
check("other IP not affected", client("amoss", "Wash1ngton-Twp-1993").get("/").status_code == 200)
# login_attempts table cannot be flooded
c = fresh_ip_client()
for i in range(200):
    c.post("/login", data={"username": f"junk{i}", "password": "x", "csrf_token": "t"})
with app.app_context():
    rows = get_db().execute("SELECT COUNT(*) FROM login_attempts WHERE ip = ?", (c.environ_base["REMOTE_ADDR"],)).fetchone()[0]
check("login_attempts flood bounded", rows <= 30, rows)

# session lifetime
check("session cookie lifetime <= 1 day", app.permanent_session_lifetime.total_seconds() <= 86400,
      app.permanent_session_lifetime)

# manager reports must not leak compensation of peers / superiors
tw = client("twellick", "Joanna&Me-Forever09")
r = post(tw, "/reports/", {"title": "p", "report_type": "payroll", "date_from": "2000-01-01", "date_to": "2030-01-01"})
d = tw.get(r.headers["Location"]).data
check("manager payroll: no boss salary", b"Terry Colby" not in d and b"650,000" not in d)
check("manager payroll: no peer salary", b"Scott Knowles" not in d)
check("manager payroll: own row present", b"Tyrell Wellick" in d)
csvd = tw.get(r.headers["Location"] + "/export.csv").data
check("manager payroll CSV: no boss salary", b"Terry Colby" not in csvd)
r = post(tw, "/reports/", {"title": "w", "report_type": "wallet", "date_from": "2000-01-01", "date_to": "2030-01-01"})
d = tw.get(r.headers["Location"]).data
check("manager wallet report: largest payroll is not the boss's", b"54,166.66" not in d)
tc = client("tcolby", "C0lby!CTO-Golf94")
r = post(tc, "/reports/", {"title": "p", "report_type": "payroll", "date_from": "2000-01-01", "date_to": "2030-01-01"})
d = tc.get(r.headers["Location"]).data
check("CTO payroll: sees his reports", b"Tyrell Wellick" in d and b"Scott Knowles" in d)
check("CTO payroll: no CEO salary", b"Phillip Price" not in d)
r = post(admin, "/reports/", {"title": "p", "report_type": "payroll", "date_from": "2000-01-01", "date_to": "2030-01-01", "department": ""})
d = admin.get(r.headers["Location"]).data
check("admin payroll: sees everyone", b"Phillip Price" in d and b"Rachel Stone" in d)
# manager cannot widen scope by sending department / scope fields
r = post(tw, "/reports/", {"title": "p", "report_type": "payroll", "date_from": "2000-01-01", "date_to": "2030-01-01",
                           "department": "", "scope_user_id": "", "author_id": "1"})
d = tw.get(r.headers["Location"]).data
check("manager cannot override report scope", b"Phillip Price" not in d and b"Terry Colby" not in d)

# admin: salary bounds, no 500
for sal in ["9" * 30, str(2 ** 62), "-5"]:
    r = post(admin, "/admin/users/13", {"full_name": "Oliver Grant", "email": "ogrant@e-corp.com", "role": "employee",
                                        "department": "Finance", "title": "Financial Analyst", "salary": sal, "is_active": "on"})
    check(f"admin salary {sal[:12]}… rejected without 500", r.status_code == 200 and b"Invalid" in r.data, r.status_code)

# concurrent transfers: no 500s, no double spend
lc_ip = []
def go(res):
    c = client("lchen", "EC0in-Ledger-2008")
    res.append(post(c, "/wallet/transfer", {"recipient": "ogrant", "amount": "1"}).status_code)
res = []
ths = [threading.Thread(target=go, args=(res,)) for _ in range(20)]
[t.start() for t in ths]; [t.join() for t in ths]
check("20 parallel transfers: no server errors", res.count(302) == 20, {x: res.count(x) for x in set(res)})
with app.app_context():
    db = get_db()
    total_bal = db.execute("SELECT SUM(balance) FROM users").fetchone()[0]
    minted = db.execute("SELECT SUM(amount) FROM transactions WHERE kind = 'payroll'").fetchone()[0]
check("E Coin conserved (sum of balances == payroll minted)", total_bal == minted, f"{total_bal} vs {minted}")

# self-registration hardening
def register(c, username, email, name="Phillip Price"):
    return c.post("/register", data={"csrf_token": "t", "username": username, "full_name": name, "email": email,
                                      "password": "password123", "confirm": "password123"})
c = fresh_ip_client()
check("register with @e-corp.com email blocked", b"already have an account" in register(c, "pprice2", "ceo@e-corp.com").data)
check("register with sub.e-corp.com email blocked", b"already have an account" in register(c, "pprice3", "a@mail.e-corp.com").data)
for name in ["admin", "admin2", "it-helpdesk", "helpdesk", "security", "payroll", "root"]:
    check(f"reserved username {name!r} blocked", b"reserved" in register(c, name, f"{name}@x.io").data)
c = fresh_ip_client()
codes = [register(c, f"spam{i}", f"spam{i}@x.io", "Spam").status_code for i in range(8)]
check("registration rate limit per IP", codes.count(302) == 5 and codes[-1] == 429, codes)

for st, n, i in R:
    print(st, n, ("  ["+str(i)+"]") if i != "" else "")
issues = sum(1 for s, _, _ in R if s == "VULN")
print("\nTOTAL issues:", issues, "/", len(R))
sys.exit(1 if issues else 0)

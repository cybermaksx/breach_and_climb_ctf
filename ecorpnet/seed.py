"""Demo data for ECorpNet: E Corp staff, documents, tickets, announcements and E Coin history."""
import os
import uuid
from datetime import date

from werkzeug.security import generate_password_hash

from .wallet import run_payroll, transfer

# username, full name, role, department, title, salary, manager, phone, office, hired, password
USERS = [
    ("pprice", "Phillip Price", "admin", "Executive", "Chief Executive Officer", 1200000, None,
     "+1 212 555 0100", "Floor 62, Corner Office", "1987-03-02", "Pr1ce-0f-P0wer#1987"),
    ("tcolby", "Terry Colby", "manager", "Technology", "Chief Technology Officer", 650000, "pprice",
     "+1 212 555 0142", "Floor 58, 5801", "1994-06-13", "C0lby!CTO-Golf94"),
    ("twellick", "Tyrell Wellick", "manager", "Technology", "Senior Vice President of Technology", 420000, "tcolby",
     "+1 212 555 0177", "Floor 58, 5812", "2009-09-01", "Joanna&Me-Forever09"),
    ("sknowles", "Scott Knowles", "manager", "Technology", "Vice President, Infrastructure", 380000, "tcolby",
     "+1 212 555 0181", "Floor 57, 5703", "2010-02-15", "Sh4ron-Kn0wles!2010"),
    ("pnair", "Priya Nair", "it", "IT Operations", "Senior Systems Administrator", 112000, "sknowles",
     "+1 212 555 0230", "Floor 12, NOC", "2011-04-04", "Nair-Sysadm1n-NOC!"),
    ("dlin", "Derek Lin", "it", "IT Operations", "IT Helpdesk Lead", 88000, "sknowles",
     "+1 212 555 0231", "Floor 12, Helpdesk", "2013-08-19", "Helpd3sk-Hero-2013"),
    ("kdoyle", "Kevin Doyle", "employee", "Security Operations", "SOC Analyst", 84000, "sknowles",
     "+1 212 555 0245", "Floor 12, SOC", "2014-01-06", "S0C-Night-Shift#14"),
    ("rhale", "Richard Hale", "manager", "Risk Management", "Director of Risk Management", 230000, "pprice",
     "+1 212 555 0310", "Floor 40, 4002", "2005-11-21", "R1sk-Appetite-Zer0"),
    ("amoss", "Angela Moss", "employee", "Risk Management", "Risk Management Associate", 72000, "rhale",
     "+1 212 555 0318", "Floor 40, Open space B", "2015-05-11", "Wash1ngton-Twp-1993"),
    ("hcole", "Hannah Cole", "manager", "Human Resources", "HR Director", 210000, "pprice",
     "+1 212 555 0400", "Floor 30, 3001", "2006-07-10", "Pe0ple-F1rst-HR!"),
    ("mwebb", "Marcus Webb", "employee", "Human Resources", "HR Generalist", 68000, "hcole",
     "+1 212 555 0412", "Floor 30, Open space A", "2014-10-27", "Onb0arding-Day-1!"),
    ("lchen", "Lucy Chen", "manager", "Finance", "Payroll & Compensation Manager", 185000, "pprice",
     "+1 212 555 0500", "Floor 44, 4410", "2008-03-17", "EC0in-Ledger-2008"),
    ("ogrant", "Oliver Grant", "employee", "Finance", "Financial Analyst", 91000, "lchen",
     "+1 212 555 0517", "Floor 44, Open space C", "2013-02-04", "Spreadsh33t-Kn1ght"),
    ("rstone", "Rachel Stone", "employee", "Legal", "Corporate Counsel", 175000, "pprice",
     "+1 212 555 0600", "Floor 61, 6107", "2007-09-24", "Pr1vileged&C0nfid"),
    ("jkim", "Jason Kim", "contractor", "Contractors", "External Contractor (Allsafe Cybersecurity)", 0, None,
     "", "Visitor badge", date.today().isoformat(), "Allsafe-Visitor-01"),
]

BIOS = {
    "pprice": "Leading E Corp since 1987. Our mission: to bring the world together through technology and finance.",
    "twellick": "Driving technical excellence across E Corp. Ask me about our data center consolidation program.",
    "tcolby": "Responsible for the global technology strategy of E Corp.",
    "amoss": "Risk Management. Previously account management at Allsafe Cybersecurity.",
    "pnair": "Linux, backups, monitoring. If the NOC is quiet, something is wrong.",
    "dlin": "Your first stop for anything IT. Please open a ticket before calling.",
}

ANNOUNCEMENTS = [
    ("lchen", "E Coin is now the default payroll currency",
     "Starting this quarter, all salaries are paid in E Coin directly to your ECorpNet wallet. "
     "You can transfer E Coin to colleagues instantly from the Wallet page. "
     "Questions? Contact Finance / Payroll.", 1),
    ("kdoyle", "Mandatory security awareness training",
     "All employees and contractors must complete the annual security awareness training by the end of the month. "
     "Reminder: never share your password, and report suspicious emails to the SOC via an IT ticket "
     "(category: Security Incident).", 0),
    ("sknowles", "Scheduled maintenance: Steel Mountain backup facility",
     "The Steel Mountain data center will undergo HVAC and backup tape maintenance this Saturday 01:00-05:00. "
     "Backup restores will be unavailable during the window.", 0),
    ("pnair", "Welcome to the new ECorpNet",
     "ECorpNet has been upgraded. New features: E Coin wallet, report builder for managers and a JSON API "
     "for internal tooling (/api/v1). Please report any issues to the IT Helpdesk.", 0),
]

TICKETS = [
    ("twellick", "pnair", "Strange process consuming CPU on CS30 server", "Security Incident", "critical",
     "in_progress",
     "Monitoring shows an unknown process on CS30 consuming 90% CPU since last night. "
     "Possible DDoS related activity. Please investigate immediately.",
     [("pnair", "Found a suspicious file in the system directory. Isolating CS30 from the network."),
      ("twellick", "Keep this quiet. Report findings directly to me.")]),
    ("amoss", None, "Cannot access shared drive \\\\risk-fs01\\cases", "Access Request", "normal", "open",
     "I need read access to the Risk Management case archive for a review I'm working on. "
     "My manager Richard Hale approved this verbally.", []),
    ("ogrant", "dlin", "Laptop fan constantly running", "Hardware", "low", "resolved",
     "My laptop fan runs at full speed even when idle. Asset tag EC-LT-4471.",
     [("dlin", "Cleaned the fan and updated BIOS. Should be fine now, please confirm.")]),
    ("mwebb", None, "VPN disconnects every 10 minutes", "Network / VPN", "high", "open",
     "When working from home the VPN drops every ~10 minutes and I lose access to the HR system.", []),
    ("jkim", None, "Request ECorpNet onboarding for Allsafe team", "Access Request", "normal", "open",
     "Allsafe Cybersecurity consultants need contractor access for the incident response engagement.", []),
]

DOCUMENTS = [
    ("Employee Handbook", "Company policies, benefits and conduct for all E Corp staff.", "HR", "all",
     "employee_handbook.txt", "hcole",
     """E CORP EMPLOYEE HANDBOOK
=======================

1. Welcome
   Welcome to E Corp, one of the largest conglomerates in the world. Every employee
   contributes to our mission of shaping the future of technology and finance.

2. Working hours
   Core hours are 09:00-17:00. Remote work requires manager approval.

3. Compensation
   Salaries are paid monthly in E Coin to your ECorpNet wallet.

4. IT and security
   All IT requests go through the IT Helpdesk ticket system on ECorpNet.
   Your username is your first initial followed by your last name (e.g. jsmith).

5. Confidentiality
   Internal information must never be shared outside E Corp.
"""),
    ("IT Acceptable Use Policy", "Rules for use of E Corp computing resources.", "IT", "all",
     "it_acceptable_use_policy.txt", "pnair",
     """IT ACCEPTABLE USE POLICY  (rev. 4)
---------------------------------
- Company systems are for business use. All activity is logged and monitored.
- Passwords must be at least 8 characters and must not be reused across systems.
- Do not install unapproved software.
- Report lost devices and suspected incidents to the SOC immediately.
- Contractors receive limited ECorpNet access until sponsored by an employee.
"""),
    ("Code of Conduct", "Ethics and business conduct guidelines.", "Policy", "employee",
     "code_of_conduct.txt", "rstone",
     """E CORP CODE OF CONDUCT
---------------------
We act with integrity. We comply with the law. We protect company assets.
Any concerns may be raised confidentially with Legal (Rachel Stone).
"""),
    ("Compensation Bands 2015", "Salary bands by grade. Managers only.", "Finance", "manager",
     "compensation_bands_2015.csv", "lchen",
     """grade,title_example,min_ec,mid_ec,max_ec
E1,Associate,55000,68000,80000
E2,Analyst,75000,90000,110000
E3,Senior,100000,120000,145000
M1,Manager,140000,175000,210000
M2,Director,190000,230000,280000
X1,Vice President,300000,380000,450000
X2,SVP,400000,450000,550000
"""),
    ("Board Briefing Q3 (Confidential)", "Executive briefing for the board. Do not distribute.", "Executive",
     "admin", "board_briefing_q3.txt", "pprice",
     """CONFIDENTIAL - BOARD BRIEFING Q3
================================
1. E Coin adoption: 61% of payroll and 23% of retail transactions now in E Coin.
2. Washington Township litigation: settlement strategy remains unchanged.
   Legal advises that internal documents from 1993 remain archived off-site.
3. Infrastructure: data center consolidation at Steel Mountain on track.
4. Security: CS30 incident contained. External firm Allsafe retained.
"""),
]

TRANSFERS = [
    ("twellick", "sknowles", 150000, "Lunch at Le Bernardin, thanks"),
    ("amoss", "ogrant", 4500, "Coffee run"),
    ("rhale", "amoss", 50000, "Great work on the quarterly review"),
    ("dlin", "pnair", 2000, "Pizza for the night shift"),
]


def _previous_periods(n):
    today = date.today()
    y, m = today.year, today.month
    periods = []
    for _ in range(n):
        m -= 1
        if m == 0:
            y, m = y - 1, 12
        periods.append(f"{y:04d}-{m:02d}")
    return list(reversed(periods))


def seed(db, documents_dir):
    ids = {}
    for (username, name, role, dept, title, salary, _mgr, phone, office, hired, password) in USERS:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, full_name, email, role, department, title, phone, office,"
            " bio, salary, hired_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (username, generate_password_hash(password), name, f"{username}@e-corp.com", role, dept, title,
             phone, office, BIOS.get(username, ""), salary, hired),
        )
        ids[username] = cur.lastrowid
    for (username, *_rest) in USERS:
        manager = _rest[5]
        if manager:
            db.execute("UPDATE users SET manager_id = ? WHERE id = ?", (ids[manager], ids[username]))

    for author, title, body, pinned in ANNOUNCEMENTS:
        db.execute(
            "INSERT INTO announcements (author_id, title, body, pinned) VALUES (?, ?, ?, ?)",
            (ids[author], title, body, pinned),
        )

    for author, assignee, subject, category, priority, status, body, comments in TICKETS:
        cur = db.execute(
            "INSERT INTO tickets (author_id, assignee_id, subject, category, priority, status, body)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ids[author], ids.get(assignee), subject, category, priority, status, body),
        )
        for c_author, c_body in comments:
            db.execute(
                "INSERT INTO ticket_comments (ticket_id, author_id, body) VALUES (?, ?, ?)",
                (cur.lastrowid, ids[c_author], c_body),
            )

    os.makedirs(documents_dir, exist_ok=True)
    for name in os.listdir(documents_dir):
        os.remove(os.path.join(documents_dir, name))
    for title, desc, category, clearance, filename, uploader, content in DOCUMENTS:
        stored = f"{uuid.uuid4().hex}.{filename.rsplit('.', 1)[1]}"
        with open(os.path.join(documents_dir, stored), "w") as f:
            f.write(content)
        db.execute(
            "INSERT INTO documents (title, description, category, clearance, stored_name, original_name, size,"
            " uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (title, desc, category, clearance, stored, filename, len(content.encode()), ids[uploader]),
        )
    db.commit()

    for period in _previous_periods(2):
        run_payroll(db, period, ids["pprice"])
    for sender, recipient, cents, memo in TRANSFERS:
        transfer(db, ids[sender], ids[recipient], cents, memo)

    return [(u[0], u[10], u[2]) for u in USERS]

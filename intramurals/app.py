"""
UC Main Intramurals System
Python (Flask) + sqlite3 + Bootstrap 5

Run:
    pip install flask
    python app.py
Open: http://127.0.0.1:5000

Default admin  ->  username: admin   password: Admin@123
Demo accounts  ->  tm1 (tournament manager), coach1, dean1   password: Pass@123
"""
import os
import re
import sqlite3
from functools import wraps

from flask import Flask, g, session, render_template, request, redirect, url_for, flash
from jinja2 import DictLoader
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "Intramurals.db")
LOCAL_CSS = os.path.join(BASE_DIR, "static", "bootstrap.min.css")

app = Flask(__name__)
app.secret_key = "skilltest-intramurals"

ROLES = ["admin", "athlete", "tournament manager", "coach", "dean"]
STAFF = {"tournament manager": "TournamentManager", "coach": "Coach", "dean": "Dean"}
CATEGORIES = ["Athletic", "Cultural", "Academic"]

# ----------------------------------------------------------------------
# DATABASE
# ----------------------------------------------------------------------
STAFF_TABLE = """
CREATE TABLE IF NOT EXISTS {name} (
    userName TEXT PRIMARY KEY,
    fName    TEXT NOT NULL,
    lName    TEXT NOT NULL,
    mobile   TEXT,
    deptID   TEXT NOT NULL,
    FOREIGN KEY (userName) REFERENCES Registration(userName),
    FOREIGN KEY (deptID)   REFERENCES Department(deptID)
);
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS Registration (
    userName        TEXT PRIMARY KEY,
    password        TEXT NOT NULL,
    confirmPassword TEXT NOT NULL,
    role            TEXT NOT NULL
        CHECK (role IN ('admin','athlete','tournament manager','coach','dean'))
);

CREATE TABLE IF NOT EXISTS Department (
    deptID   TEXT PRIMARY KEY,
    deptName TEXT NOT NULL
);
""" + "".join(STAFF_TABLE.format(name=n) for n in STAFF.values()) + """
CREATE TABLE IF NOT EXISTS Event (
    eventID           INTEGER PRIMARY KEY AUTOINCREMENT,
    category          TEXT NOT NULL CHECK (category IN ('Athletic','Cultural','Academic')),
    eventName         TEXT NOT NULL,
    noOfParticipant   INTEGER NOT NULL,
    tournamentManager TEXT NOT NULL,
    FOREIGN KEY (tournamentManager) REFERENCES TournamentManager(userName)
);

CREATE TABLE IF NOT EXISTS AthletesProfile (
    idNum        TEXT PRIMARY KEY,
    eventID      INTEGER NOT NULL,
    deptID       TEXT NOT NULL,
    lastName     TEXT NOT NULL,
    firstName    TEXT NOT NULL,
    middleInit   TEXT,
    course       TEXT,
    year         INTEGER,
    civilStatus  TEXT,
    gender       TEXT,
    birthdate    TEXT,
    contactNo    TEXT,
    address      TEXT,
    coachID      TEXT NOT NULL,
    deanID       TEXT NOT NULL,
    FOREIGN KEY (idNum)   REFERENCES Registration(userName),
    FOREIGN KEY (eventID) REFERENCES Event(eventID),
    FOREIGN KEY (deptID)  REFERENCES Department(deptID),
    FOREIGN KEY (coachID) REFERENCES Coach(userName),
    FOREIGN KEY (deanID)  REFERENCES Dean(userName)
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript(SCHEMA)
    if db.execute("SELECT COUNT(*) FROM Registration").fetchone()[0] == 0:
        def reg(user, pw, role):
            h = generate_password_hash(pw)
            db.execute("INSERT INTO Registration VALUES (?,?,?,?)", (user, h, h, role))

        reg("admin", "Admin@123", "admin")
        db.executemany(
            "INSERT INTO Department VALUES (?,?)",
            [("CCS", "College of Computer Studies"),
             ("CBA", "College of Business and Accountancy"),
             ("CAS", "College of Arts and Sciences")],
        )
        reg("tm1", "Pass@123", "tournament manager")
        reg("coach1", "Pass@123", "coach")
        reg("dean1", "Pass@123", "dean")
        db.execute("INSERT INTO TournamentManager VALUES ('tm1','Tina','Manalo','09170000001','CCS')")
        db.execute("INSERT INTO Coach VALUES ('coach1','Carlo','Reyes','09170000002','CCS')")
        db.execute("INSERT INTO Dean VALUES ('dean1','Dino','Santos','09170000003','CCS')")
        db.executemany(
            "INSERT INTO Event (category, eventName, noOfParticipant, tournamentManager) VALUES (?,?,?,'tm1')",
            [("Athletic", "Volleyball Men", 12), ("Athletic", "Volleyball Women", 12),
             ("Academic", "Quiz Bee", 5), ("Cultural", "Singing Contest", 3)],
        )
    db.commit()
    db.close()


# ----------------------------------------------------------------------
# HELPERS
# ----------------------------------------------------------------------
@app.context_processor
def inject_globals():
    return {
        "use_local_css": os.path.exists(LOCAL_CSS),
        "me": session.get("user"),
        "my_role": session.get("role"),
    }


def login_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if "user" not in session:
                flash("Please log in first.", "err")
                return redirect(url_for("login"))
            if roles and session["role"] not in roles:
                flash("You are not allowed to open that page.", "err")
                return redirect(url_for("menu"))
            return f(*a, **kw)
        return wrapper
    return deco


def strong_password(pw):
    """letters + numbers + special characters, at least 8 chars"""
    return (
        len(pw) >= 8
        and re.search(r"[A-Za-z]", pw)
        and re.search(r"\d", pw)
        and re.search(r"[^A-Za-z0-9]", pw)
    )


def has_profile(user, role):
    db = get_db()
    if role == "athlete":
        q, args = "SELECT 1 FROM AthletesProfile WHERE idNum=?", (user,)
    elif role in STAFF:
        q, args = f"SELECT 1 FROM {STAFF[role]} WHERE userName=?", (user,)
    else:
        return True
    return db.execute(q, args).fetchone() is not None


# ----------------------------------------------------------------------
# MENU
# ----------------------------------------------------------------------
@app.route("/")
def menu():
    return render_template("menu.html")


# ----------------------------------------------------------------------
# REGISTRATION + LOGIN
# ----------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user = request.form["userName"].strip()
        pw = request.form["password"]
        cp = request.form["confirmPassword"]
        role = request.form["role"]
        if not user:
            flash("Username (ID number) is required.", "err")
        elif role not in ROLES:
            flash("Please choose a role.", "err")
        elif not strong_password(pw):
            flash("Password must be at least 8 characters and contain letters, "
                  "numbers and special characters.", "err")
        elif pw != cp:
            flash("Passwords do not match.", "err")
        else:
            h = generate_password_hash(pw)
            try:
                get_db().execute("INSERT INTO Registration VALUES (?,?,?,?)", (user, h, h, role))
                get_db().commit()
                flash("Registration successful. You can now log in.", "ok")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already registered.", "err")
    return render_template("register.html", roles=ROLES)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form["userName"].strip()
        row = get_db().execute("SELECT * FROM Registration WHERE userName=?", (user,)).fetchone()
        if row and check_password_hash(row["password"], request.form["password"]):
            session["user"], session["role"] = row["userName"], row["role"]
            flash(f"Welcome, {user}!", "ok")
            if not has_profile(row["userName"], row["role"]):
                flash("Please complete your profile first.", "err")
                return redirect(url_for("profile"))
            return redirect(url_for("menu"))
        flash("Invalid username or password.", "err")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "ok")
    return redirect(url_for("menu"))


# ----------------------------------------------------------------------
# DEPARTMENT MANAGEMENT (Admin)
# ----------------------------------------------------------------------
@app.route("/departments", methods=["GET", "POST"])
@login_required("admin")
def departments():
    db = get_db()
    if request.method == "POST":
        try:
            db.execute("INSERT INTO Department VALUES (?,?)",
                       (request.form["deptID"].strip().upper(), request.form["deptName"].strip()))
            db.commit()
            flash("Department created.", "ok")
        except sqlite3.IntegrityError:
            flash("Department ID already exists.", "err")
        return redirect(url_for("departments"))
    rows = db.execute("SELECT * FROM Department ORDER BY deptID").fetchall()
    return render_template("departments.html", rows=rows)


@app.route("/departments/delete/<dept_id>", methods=["POST"])
@login_required("admin")
def department_delete(dept_id):
    try:
        get_db().execute("DELETE FROM Department WHERE deptID=?", (dept_id,))
        get_db().commit()
        flash("Department deleted.", "ok")
    except sqlite3.IntegrityError:
        flash("Cannot delete: department is still in use.", "err")
    return redirect(url_for("departments"))


# ----------------------------------------------------------------------
# PROFILE (Athlete / Tournament Manager / Coach / Dean)
# ----------------------------------------------------------------------
@app.route("/profile", methods=["GET", "POST"])
@login_required("athlete", "tournament manager", "coach", "dean")
def profile():
    db = get_db()
    user, role = session["user"], session["role"]
    deps = db.execute("SELECT * FROM Department ORDER BY deptID").fetchall()

    # ---- staff profile ------------------------------------------------
    if role in STAFF:
        table = STAFF[role]
        p = db.execute(f"SELECT * FROM {table} WHERE userName=?", (user,)).fetchone()
        if request.method == "POST":
            f = request.form
            try:
                db.execute(
                    f"INSERT INTO {table} VALUES (?,?,?,?,?) ON CONFLICT(userName) DO UPDATE SET "
                    "fName=excluded.fName, lName=excluded.lName, mobile=excluded.mobile, deptID=excluded.deptID",
                    (user, f["fName"].strip(), f["lName"].strip(), f["mobile"].strip(), f["deptID"]),
                )
                db.commit()
                flash("Profile saved.", "ok")
                return redirect(url_for("menu"))
            except sqlite3.IntegrityError:
                flash("Invalid department.", "err")
        return render_template("profile.html", p=p, deps=deps, role=role)

    # ---- athlete profile ----------------------------------------------
    p = db.execute("SELECT * FROM AthletesProfile WHERE idNum=?", (user,)).fetchone()
    coaches = db.execute("SELECT * FROM Coach ORDER BY lName").fetchall()
    deans = db.execute("SELECT * FROM Dean ORDER BY lName").fetchall()
    events = db.execute(
        "SELECT e.*, (SELECT COUNT(*) FROM AthletesProfile a "
        "WHERE a.eventID = e.eventID AND a.idNum != ?) AS taken "
        "FROM Event e ORDER BY e.category, e.eventName", (user,)
    ).fetchall()
    if request.method == "POST":
        f = request.form
        try:
            ev = next((e for e in events if e["eventID"] == int(f["eventID"])), None)
            if ev is None:
                flash("Please choose an event.", "err")
            elif ev["taken"] >= ev["noOfParticipant"]:
                flash("Sorry, that event is already full.", "err")
            else:
                db.execute(
                    "INSERT OR REPLACE INTO AthletesProfile VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (user, ev["eventID"], f["deptID"], f["lastName"].strip(), f["firstName"].strip(),
                     f["middleInit"].strip()[:1], f["course"].strip(), int(f["year"]),
                     f["civilStatus"], f["gender"], f["birthdate"], f["contactNo"].strip(),
                     f["address"].strip(), f["coachID"], f["deanID"]),
                )
                db.commit()
                flash("Athlete profile saved.", "ok")
                return redirect(url_for("menu"))
        except (sqlite3.IntegrityError, ValueError, KeyError):
            flash("Please complete all fields correctly.", "err")
    return render_template("profile.html", p=p, deps=deps, role=role,
                           coaches=coaches, deans=deans, events=events)


# ----------------------------------------------------------------------
# EVENTS (Tournament Manager creates; everyone logged in can view)
# ----------------------------------------------------------------------
@app.route("/events", methods=["GET", "POST"])
@login_required()
def events():
    db = get_db()
    if request.method == "POST":
        if session["role"] != "tournament manager":
            flash("Only tournament managers can create events.", "err")
            return redirect(url_for("events"))
        try:
            n = int(request.form["noOfParticipant"])
            if request.form["category"] not in CATEGORIES or n < 1:
                raise ValueError
            db.execute(
                "INSERT INTO Event (category, eventName, noOfParticipant, tournamentManager) VALUES (?,?,?,?)",
                (request.form["category"], request.form["eventName"].strip(), n, session["user"]),
            )
            db.commit()
            flash("Event created.", "ok")
        except sqlite3.IntegrityError:
            flash("Please complete your profile before creating events.", "err")
        except ValueError:
            flash("Invalid event data.", "err")
        return redirect(url_for("events"))
    rows = db.execute(
        "SELECT e.*, (SELECT COUNT(*) FROM AthletesProfile a WHERE a.eventID = e.eventID) AS taken, "
        "t.fName || ' ' || t.lName AS mgr "
        "FROM Event e LEFT JOIN TournamentManager t ON t.userName = e.tournamentManager "
        "ORDER BY e.category, e.eventName"
    ).fetchall()
    return render_template("events.html", rows=rows, categories=CATEGORIES)


@app.route("/events/delete/<int:event_id>", methods=["POST"])
@login_required("tournament manager")
def event_delete(event_id):
    try:
        get_db().execute("DELETE FROM Event WHERE eventID=? AND tournamentManager=?",
                         (event_id, session["user"]))
        get_db().commit()
        flash("Event deleted.", "ok")
    except sqlite3.IntegrityError:
        flash("Cannot delete: athletes are registered in this event.", "err")
    return redirect(url_for("events"))


# ----------------------------------------------------------------------
# ATHLETES LIST (Admin / Tournament Manager / Coach / Dean)
# ----------------------------------------------------------------------
@app.route("/athletes")
@login_required("admin", "tournament manager", "coach", "dean")
def athletes():
    role, user = session["role"], session["user"]
    sql = (
        "SELECT a.*, e.eventName, d.deptName, "
        "c.fName || ' ' || c.lName AS coachName, n.fName || ' ' || n.lName AS deanName "
        "FROM AthletesProfile a "
        "LEFT JOIN Event e ON e.eventID = a.eventID "
        "LEFT JOIN Department d ON d.deptID = a.deptID "
        "LEFT JOIN Coach c ON c.userName = a.coachID "
        "LEFT JOIN Dean n ON n.userName = a.deanID "
    )
    args = ()
    if role == "tournament manager":
        sql, args = sql + "WHERE e.tournamentManager = ? ", (user,)
    elif role == "coach":
        sql, args = sql + "WHERE a.coachID = ? ", (user,)
    elif role == "dean":
        sql, args = sql + "WHERE a.deanID = ? ", (user,)
    rows = get_db().execute(sql + "ORDER BY a.lastName", args).fetchall()
    return render_template("athletes.html", rows=rows)


# ----------------------------------------------------------------------
# TEMPLATES (inline so the whole project is a single file)
# ----------------------------------------------------------------------
TEMPLATES = {
    "base.html": """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UC Main Intramurals System</title>
{% if use_local_css %}
<link href="{{ url_for('static', filename='bootstrap.min.css') }}" rel="stylesheet">
{% else %}
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
{% endif %}
</head>
<body>
<nav class="navbar navbar-dark bg-dark mb-4">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('menu') }}">UC Main Intramurals System</a>
    {% if me %}<span class="navbar-text text-white">{{ me }} ({{ my_role }})
      &nbsp;<a class="btn btn-sm btn-outline-light" href="{{ url_for('logout') }}">Logout</a></span>{% endif %}
  </div>
</nav>
<div class="container pb-5">
{% with msgs = get_flashed_messages(with_categories=true) %}
  {% for cat, m in msgs %}
  <div class="alert alert-{{ 'success' if cat == 'ok' else 'danger' }}">{{ m }}</div>
  {% endfor %}
{% endwith %}
{% block content %}{% endblock %}
</div>
</body></html>""",

    "menu.html": """{% extends 'base.html' %}{% block content %}
<h3>Main Menu</h3>
<div class="list-group col-md-6 mt-3">
{% if not me %}
 <a class="list-group-item list-group-item-action" href="{{ url_for('register') }}">Registration</a>
 <a class="list-group-item list-group-item-action" href="{{ url_for('login') }}">Login</a>
{% else %}
 {% if my_role == 'admin' %}
 <a class="list-group-item list-group-item-action" href="{{ url_for('departments') }}">Department Management</a>
 {% endif %}
 {% if my_role != 'admin' %}
 <a class="list-group-item list-group-item-action" href="{{ url_for('profile') }}">My Profile</a>
 {% endif %}
 <a class="list-group-item list-group-item-action" href="{{ url_for('events') }}">
   {{ 'Event Management' if my_role == 'tournament manager' else 'Events' }}</a>
 {% if my_role in ['admin', 'tournament manager', 'coach', 'dean'] %}
 <a class="list-group-item list-group-item-action" href="{{ url_for('athletes') }}">Athletes List</a>
 {% endif %}
 <a class="list-group-item list-group-item-action" href="{{ url_for('logout') }}">Logout</a>
{% endif %}
</div>{% endblock %}""",

    "register.html": """{% extends 'base.html' %}{% block content %}
<h3>Registration</h3>
<form method="post" class="col-md-5">
 <div class="mb-3"><label class="form-label">Username (Student's/Employee's ID Number)</label>
  <input class="form-control" name="userName" required></div>
 <div class="mb-3"><label class="form-label">Password</label>
  <input class="form-control" type="password" name="password" required>
  <div class="form-text">At least 8 characters with letters, numbers and special characters.</div></div>
 <div class="mb-3"><label class="form-label">Confirm Password</label>
  <input class="form-control" type="password" name="confirmPassword" required></div>
 <div class="mb-3"><label class="form-label">Role</label>
  <select class="form-select" name="role" required>
   {% for r in roles %}<option value="{{ r }}">{{ r | title }}</option>{% endfor %}
  </select></div>
 <button class="btn btn-success">Register</button>
 <a class="btn btn-secondary" href="{{ url_for('login') }}">Go to Login</a>
</form>{% endblock %}""",

    "login.html": """{% extends 'base.html' %}{% block content %}
<h3>Login</h3>
<form method="post" class="col-md-4">
 <div class="mb-3"><label class="form-label">Username</label>
  <input class="form-control" name="userName" required></div>
 <div class="mb-3"><label class="form-label">Password</label>
  <input class="form-control" type="password" name="password" required></div>
 <button class="btn btn-primary">Login</button>
 <a class="btn btn-secondary" href="{{ url_for('register') }}">Register</a>
</form>{% endblock %}""",

    "departments.html": """{% extends 'base.html' %}{% block content %}
<h3>Department Management</h3>
<a class="btn btn-secondary mb-3" href="{{ url_for('menu') }}">Back to Menu</a>
<form method="post" class="row g-2 mb-3">
 <div class="col-md-3"><input class="form-control" name="deptID" placeholder="Dept. ID (e.g. CCS)" required></div>
 <div class="col-md-5"><input class="form-control" name="deptName" placeholder="Department Name" required></div>
 <div class="col-md-2"><button class="btn btn-primary">Create</button></div>
</form>
<table class="table table-bordered table-striped text-center align-middle">
<thead class="table-dark"><tr><th>Dept. ID</th><th>Department Name</th><th>Action</th></tr></thead>
{% for r in rows %}
<tr><td>{{ r.deptID }}</td><td>{{ r.deptName }}</td>
<td><form class="d-inline" method="post" action="{{ url_for('department_delete', dept_id=r.deptID) }}"
  onsubmit="return confirm('Delete this department?')"><button class="btn btn-sm btn-danger">Del</button></form></td></tr>
{% endfor %}
</table>{% endblock %}""",

    "profile.html": """{% extends 'base.html' %}{% block content %}
<h3>My Profile ({{ role | title }})</h3>
{% if not deps %}<div class="alert alert-warning">No departments yet. Ask the admin to create one first.</div>{% endif %}
<form method="post" class="col-md-7">
{% if role == 'athlete' %}
 {% if not events or not coaches or not deans %}
 <div class="alert alert-warning">An event, a coach and a dean must exist before an athlete can register.</div>
 {% endif %}
 <div class="mb-3"><label class="form-label">ID Number</label>
  <input class="form-control" value="{{ me }}" readonly></div>
 <div class="mb-3"><label class="form-label">Event</label>
  <select class="form-select" name="eventID" required>
   {% for e in events %}
   <option value="{{ e.eventID }}" {{ 'selected' if p and p.eventID == e.eventID }}
     {{ 'disabled' if e.taken >= e.noOfParticipant }}>
     {{ e.category }} - {{ e.eventName }} ({{ e.taken }}/{{ e.noOfParticipant }}){{ ' FULL' if e.taken >= e.noOfParticipant }}</option>
   {% endfor %}
  </select></div>
 <div class="mb-3"><label class="form-label">Department</label>
  <select class="form-select" name="deptID" required>
   {% for d in deps %}<option value="{{ d.deptID }}" {{ 'selected' if p and p.deptID == d.deptID }}>{{ d.deptID }} - {{ d.deptName }}</option>{% endfor %}
  </select></div>
 <div class="row">
  <div class="col-md-5 mb-3"><label class="form-label">Last Name</label>
   <input class="form-control" name="lastName" required value="{{ p.lastName if p }}"></div>
  <div class="col-md-5 mb-3"><label class="form-label">First Name</label>
   <input class="form-control" name="firstName" required value="{{ p.firstName if p }}"></div>
  <div class="col-md-2 mb-3"><label class="form-label">M.I.</label>
   <input class="form-control" name="middleInit" maxlength="1" value="{{ p.middleInit if p }}"></div>
 </div>
 <div class="row">
  <div class="col-md-8 mb-3"><label class="form-label">Course</label>
   <input class="form-control" name="course" required value="{{ p.course if p }}"></div>
  <div class="col-md-4 mb-3"><label class="form-label">Year</label>
   <select class="form-select" name="year">
    {% for y in [1,2,3,4,5] %}<option value="{{ y }}" {{ 'selected' if p and p.year == y }}>{{ y }}</option>{% endfor %}
   </select></div>
 </div>
 <div class="row">
  <div class="col-md-6 mb-3"><label class="form-label">Civil Status</label>
   <select class="form-select" name="civilStatus">
    {% for s in ['Single','Married','Widowed','Separated'] %}<option {{ 'selected' if p and p.civilStatus == s }}>{{ s }}</option>{% endfor %}
   </select></div>
  <div class="col-md-6 mb-3"><label class="form-label">Gender</label>
   <select class="form-select" name="gender">
    {% for s in ['Male','Female'] %}<option {{ 'selected' if p and p.gender == s }}>{{ s }}</option>{% endfor %}
   </select></div>
 </div>
 <div class="row">
  <div class="col-md-6 mb-3"><label class="form-label">Birthdate</label>
   <input class="form-control" type="date" name="birthdate" required value="{{ p.birthdate if p }}"></div>
  <div class="col-md-6 mb-3"><label class="form-label">Contact No.</label>
   <input class="form-control" name="contactNo" required value="{{ p.contactNo if p }}"></div>
 </div>
 <div class="mb-3"><label class="form-label">Address</label>
  <input class="form-control" name="address" required value="{{ p.address if p }}"></div>
 <div class="mb-3"><label class="form-label">Coach</label>
  <select class="form-select" name="coachID" required>
   {% for c in coaches %}<option value="{{ c.userName }}" {{ 'selected' if p and p.coachID == c.userName }}>{{ c.userName }} - {{ c.lName }}, {{ c.fName }}</option>{% endfor %}
  </select></div>
 <div class="mb-3"><label class="form-label">Dean</label>
  <select class="form-select" name="deanID" required>
   {% for c in deans %}<option value="{{ c.userName }}" {{ 'selected' if p and p.deanID == c.userName }}>{{ c.userName }} - {{ c.lName }}, {{ c.fName }}</option>{% endfor %}
  </select></div>
{% else %}
 <div class="mb-3"><label class="form-label">Employee ID Number</label>
  <input class="form-control" value="{{ me }}" readonly></div>
 <div class="mb-3"><label class="form-label">First Name</label>
  <input class="form-control" name="fName" required value="{{ p.fName if p }}"></div>
 <div class="mb-3"><label class="form-label">Last Name</label>
  <input class="form-control" name="lName" required value="{{ p.lName if p }}"></div>
 <div class="mb-3"><label class="form-label">Mobile</label>
  <input class="form-control" name="mobile" required value="{{ p.mobile if p }}"></div>
 <div class="mb-3"><label class="form-label">Department</label>
  <select class="form-select" name="deptID" required>
   {% for d in deps %}<option value="{{ d.deptID }}" {{ 'selected' if p and p.deptID == d.deptID }}>{{ d.deptID }} - {{ d.deptName }}</option>{% endfor %}
  </select></div>
{% endif %}
 <button class="btn btn-success">Save</button>
 <a class="btn btn-secondary" href="{{ url_for('menu') }}">Back to Menu</a>
</form>{% endblock %}""",

    "events.html": """{% extends 'base.html' %}{% block content %}
<h3>{{ 'Event Management' if my_role == 'tournament manager' else 'Events' }}</h3>
<a class="btn btn-secondary mb-3" href="{{ url_for('menu') }}">Back to Menu</a>
{% if my_role == 'tournament manager' %}
<form method="post" class="row g-2 mb-3">
 <div class="col-md-3"><select class="form-select" name="category" required>
   {% for c in categories %}<option>{{ c }}</option>{% endfor %}</select></div>
 <div class="col-md-4"><input class="form-control" name="eventName" placeholder="Event name (e.g. Volleyball Men)" required></div>
 <div class="col-md-3"><input class="form-control" type="number" min="1" name="noOfParticipant" placeholder="No. of participants" required></div>
 <div class="col-md-2"><button class="btn btn-primary">Create</button></div>
</form>
{% endif %}
<table class="table table-bordered table-striped text-center align-middle">
<thead class="table-dark"><tr><th>ID</th><th>Category</th><th>Event Name</th><th>Participants</th><th>Tournament Manager</th>
{% if my_role == 'tournament manager' %}<th>Action</th>{% endif %}</tr></thead>
{% for r in rows %}
<tr><td>{{ r.eventID }}</td><td>{{ r.category }}</td><td>{{ r.eventName }}</td>
<td>{{ r.taken }} / {{ r.noOfParticipant }}</td><td>{{ r.mgr }}</td>
{% if my_role == 'tournament manager' %}<td>
 {% if r.tournamentManager == me %}
 <form class="d-inline" method="post" action="{{ url_for('event_delete', event_id=r.eventID) }}"
  onsubmit="return confirm('Delete this event?')"><button class="btn btn-sm btn-danger">Del</button></form>
 {% else %}-{% endif %}</td>{% endif %}</tr>
{% else %}<tr><td colspan="6">No events yet.</td></tr>{% endfor %}
</table>{% endblock %}""",

    "athletes.html": """{% extends 'base.html' %}{% block content %}
<h3>Athletes List</h3>
<a class="btn btn-secondary mb-3" href="{{ url_for('menu') }}">Back to Menu</a>
<div class="table-responsive">
<table class="table table-bordered table-striped text-center align-middle">
<thead class="table-dark"><tr><th>ID</th><th>Name</th><th>Event</th><th>Department</th><th>Course/Year</th>
<th>Gender</th><th>Birthdate</th><th>Contact</th><th>Coach</th><th>Dean</th></tr></thead>
{% for r in rows %}
<tr><td>{{ r.idNum }}</td><td>{{ r.lastName }}, {{ r.firstName }} {{ r.middleInit }}</td><td>{{ r.eventName }}</td>
<td>{{ r.deptName }}</td><td>{{ r.course }} - {{ r.year }}</td><td>{{ r.gender }}</td><td>{{ r.birthdate }}</td>
<td>{{ r.contactNo }}</td><td>{{ r.coachName }}</td><td>{{ r.deanName }}</td></tr>
{% else %}<tr><td colspan="10">No athletes found.</td></tr>{% endfor %}
</table></div>{% endblock %}""",
}
app.jinja_loader = DictLoader(TEMPLATES)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
# src/app_phase2_fixed.py
from flask import Flask, request, render_template_string, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import time
import re

DB = 'phase2.db'
app = Flask(__name__)

LOCK_THRESHOLD = 3
LOCK_TIME_SECONDS = 300   # e.g., 5 minutes lockout for demo

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB)
        # enable row access by name if desired: db.row_factory = sqlite3.Row
    return db

def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            failed INTEGER DEFAULT 0,
            locked_until INTEGER DEFAULT 0
        );
    """)
    # store a strong PBKDF2 hash for demo user (do not rehash every start in real apps)
    pw_hash = generate_password_hash("Password123!", method="pbkdf2:sha256", salt_length=16)
    try:
        cur.execute("INSERT INTO users (username,password) VALUES (?,?)", ("testuser", pw_hash))
    except sqlite3.IntegrityError:
        # if user exists, ensure password is updated to pw_hash for testing
        cur.execute("UPDATE users SET password=? WHERE username=?", (pw_hash, "testuser"))
    conn.commit()
    conn.close()

login_form = '''
<h2>Fixed Login (Phase 2) — PBKDF2 + Lockout (demo)</h2>
<form method="POST" action="/login">
  Username: <input name="username"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Login">
</form>
'''

@app.route('/')
def index():
    return render_template_string(login_form)

# Keep SQLi endpoint present (lab-only) so hash can still be extracted:
@app.route('/sqli')
def sqli():
    name = request.args.get('name','')
    db = get_db()
    cur = db.cursor()
    try:
        # intentionally vulnerable (lab-only) — DO NOT use in production
        cur.execute(f"SELECT username, password, failed, locked_until FROM users WHERE username = '{name}'")
        rows = cur.fetchall()
        return "<pre>" + "\n".join([f"{r[0]}:{r[1]}:failed={r[2]}:locked_until={r[3]}" for r in rows]) + "</pre>"
    except Exception as e:
        return f"SQL Error: {e}"

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username','')
    password = request.form.get('password','')
    db = get_db()
    cur = db.cursor()
    # get user record safely (parameterized)
    cur.execute("SELECT password, failed, locked_until FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    now = int(time.time())
    if not row:
        return "Login Failed"
    stored_hash, failed, locked_until = row
    if locked_until and now < locked_until:
        return f"Account locked. Try again after {locked_until - now} seconds."
    # verify hash
    if check_password_hash(stored_hash, password):
        # reset failed counter
        cur.execute("UPDATE users SET failed=0, locked_until=0 WHERE username=?", (username,))
        db.commit()
        return "Login Successful"
    else:
        # increment failed counter
        failed = failed + 1
        if failed >= LOCK_THRESHOLD:
            new_locked = now + LOCK_TIME_SECONDS
            cur.execute("UPDATE users SET failed=?, locked_until=? WHERE username=?", (failed, new_locked, username))
        else:
            cur.execute("UPDATE users SET failed=? WHERE username=?", (failed, username))
        db.commit()
        return "Login Failed"

# ---------- password policy helper (lab-only) ----------
def password_meets_policy(pw):
    """
    Server-side password policy (lab-only)
     - min length 8
     - at least 1 uppercase
     - at least 1 lowercase
     - at least 1 digit
     - at least 1 special character
    Returns (bool, [list_of_missing_reasons])
    """
    if pw is None:
        return False, ["no_password"]
    # trim leading/trailing whitespace for policy checks (optional)
    pw_stripped = pw.strip()
    missing = []

    if len(pw_stripped) < 8:
        missing.append("min_length")
    if not re.search(r"[A-Z]", pw_stripped):
        missing.append("no_upper")
    if not re.search(r"[a-z]", pw_stripped):
        missing.append("no_lower")
    if not re.search(r"[0-9]", pw_stripped):
        missing.append("no_digit")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", pw_stripped):
        missing.append("no_special")

    # If leading/trailing whitespace existed, include a note (useful in tests)
    if pw != pw_stripped:
        missing.append("trimmed_whitespace")

    return (len(missing) == 0), missing

# Lab-only endpoint to simulate password set / registration / change-password
@app.route('/set_password', methods=['POST'])
def set_password():
    username = request.form.get('username','testuser')
    password = request.form.get('password','')

    ok, reasons = password_meets_policy(password)
    if not ok:
        # Return all missing requirements joined by comma
        return "REJECTED:" + ",".join(reasons), 400

    # Store the password hash in DB so login can be tested end-to-end
    pw_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)
    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT OR IGNORE INTO users (username,password) VALUES (?,?)", (username,pw_hash))
    cur.execute("UPDATE users SET password=? WHERE username=?", (pw_hash, username))
    db.commit()

    return "ACCEPTED:password_set", 200

@app.teardown_appcontext
def close_conn(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

@app.route('/set_password_form')
def set_password_form():
    return '''
    <form method="post" action="/set_password">
      Username: <input name="username" value="testuser"><br>
      Password: <input type="password" name="password"><br>
      <input type="submit" value="Set Password">
    </form>
    '''

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)


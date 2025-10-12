# src/app_phase1_vuln.py
from flask import Flask, request, render_template_string, g
import sqlite3, hashlib

DB = 'phase1.db'
app = Flask(__name__)

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB)
    return db

def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT);")
    # store a weak MD5 hash (single-round) for demo user
    pw = hashlib.md5(b"Password123!").hexdigest()
    try:
        cur.execute("INSERT INTO users (username,password) VALUES (?,?)", ("testuser", pw))
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()

login_form = '''
<h2>Vulnerable Login (Phase 1)</h2>
<form method="POST" action="/login">
  Username: <input name="username"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Login">
</form>
'''

@app.route('/')
def index():
    return render_template_string(login_form)

# VULNERABLE login: constructs SQL unsafely (SQLi possible)
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username','')
    password = request.form.get('password','')
    # compute MD5 for comparison (weak)
    pw_md5 = hashlib.md5(password.encode()).hexdigest()
    db = get_db()
    # vulnerable query (do NOT do this in real apps)
    q = f"SELECT username FROM users WHERE username='{username}' AND password='{pw_md5}'"
    cur = db.cursor()
    try:
        cur.execute(q)
        row = cur.fetchone()
        if row:
            return "Login Successful"
    except Exception as e:
        return f"SQL Error: {e}"
    return "Login Failed"

# LAB-only: export users table (simulate DB dump / SQLi target)
@app.route('/export')
def export_users():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username, password FROM users")
    rows = cur.fetchall()
    out = "<pre>\n" + "\n".join([f"{r[0]}:{r[1]}" for r in rows]) + "\n</pre>"
    return out

# Helper: a vulnerable endpoint that directly uses the 'name' param in SQL (to show injection)
@app.route('/sqli')
def sqli():
    name = request.args.get('name','')
    db = get_db()
    cur = db.cursor()
    try:
        # intentionally unsafe
        cur.execute(f"SELECT username, password FROM users WHERE username = '{name}'")
        rows = cur.fetchall()
        return "<pre>" + "\n".join([f"{r[0]}:{r[1]}" for r in rows]) + "</pre>"
    except Exception as e:
        return f"SQL Error: {e}"

# LAB-only: set_password that accepts any password (no complexity enforcement) and stores weak MD5 hash
@app.route('/set_password', methods=['POST'])
def set_password():
    username = request.form.get('username','testuser')
    password = request.form.get('password','')
    # store as weak MD5 (intentionally insecure for Phase-1 demo)
    pw_md5 = hashlib.md5(password.encode()).hexdigest()
    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT OR IGNORE INTO users (username,password) VALUES (?,?)", (username, pw_md5))
    cur.execute("UPDATE users SET password=? WHERE username=?", (pw_md5, username))
    db.commit()
    return "ACCEPTED:password_set", 200

# Simple browser form to POST to /set_password (so you can test from browser)
@app.route('/set_password_form')
def set_password_form():
    return '''
    <form method="post" action="/set_password">
      Username: <input name="username" value="testuser"><br>
      Password: <input type="password" name="password"><br>
      <input type="submit" value="Set Password (no complexity)">
    </form>
    '''

@app.teardown_appcontext
def close_conn(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)


"""
Vulnerable Flask application — intentional security issues for CodeQL scanning.
DO NOT deploy this in production.
"""

import os
import sqlite3
import subprocess
import pickle
import hashlib
import requests
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)

# ------------------------------------------------------------------ #
# VULNERABILITY 1 – Hardcoded credentials / secret key               #
# ------------------------------------------------------------------ #
app.secret_key = "supersecretkey123"
DB_PASSWORD = "admin123"
API_KEY = "AKIAIOSFODNN7EXAMPLE"

# ------------------------------------------------------------------ #
# VULNERABILITY 2 – SQL Injection                                     #
# ------------------------------------------------------------------ #
def get_db():
    conn = sqlite3.connect("users.db")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, password TEXT)"
    )
    return conn


@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    conn = get_db()
    # SQL injection: user-controlled input concatenated directly into query
    query = f"SELECT * FROM users WHERE name='{username}' AND password='{password}'"
    cursor = conn.execute(query)
    user = cursor.fetchone()
    if user:
        return f"Welcome {user[1]}!"
    return "Invalid credentials", 401


@app.route("/user")
def get_user():
    user_id = request.args.get("id", "1")
    conn = get_db()
    # SQL injection: user-controlled id concatenated into query
    result = conn.execute("SELECT * FROM users WHERE id=" + user_id).fetchone()
    return str(result)


# ------------------------------------------------------------------ #
# VULNERABILITY 3 – OS Command Injection                              #
# ------------------------------------------------------------------ #
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Command injection: user input passed directly to shell
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output.decode()


@app.route("/exec")
def exec_cmd():
    cmd = request.args.get("cmd", "")
    # Command injection via os.system
    os.system(cmd)
    return "Done"


# ------------------------------------------------------------------ #
# VULNERABILITY 4 – Path Traversal                                    #
# ------------------------------------------------------------------ #
@app.route("/file")
def read_file():
    filename = request.args.get("name", "")
    # Path traversal: no sanitization on filename
    base_dir = "/var/www/files"
    path = os.path.join(base_dir, filename)
    with open(path, "r") as f:
        return f.read()


# ------------------------------------------------------------------ #
# VULNERABILITY 5 – Server-Side Request Forgery (SSRF)               #
# ------------------------------------------------------------------ #
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    # SSRF: arbitrary URL fetched without validation
    response = requests.get(url, timeout=5)
    return response.text


# ------------------------------------------------------------------ #
# VULNERABILITY 6 – Reflected XSS (server-side template injection)   #
# ------------------------------------------------------------------ #
@app.route("/search")
def search():
    query = request.args.get("q", "")
    # XSS: user input rendered unescaped in template
    template = f"<h1>Search results for: {query}</h1>"
    return render_template_string(template)


# ------------------------------------------------------------------ #
# VULNERABILITY 7 – Insecure Deserialization                         #
# ------------------------------------------------------------------ #
@app.route("/load", methods=["POST"])
def load_object():
    data = request.get_data()
    # Insecure deserialization: arbitrary pickle data from user
    obj = pickle.loads(data)
    return str(obj)


# ------------------------------------------------------------------ #
# VULNERABILITY 8 – Weak cryptography (MD5 for passwords)            #
# ------------------------------------------------------------------ #
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # Weak hash: MD5 is not suitable for passwords
    hashed = hashlib.md5(password.encode()).hexdigest()
    conn = get_db()
    conn.execute(
        f"INSERT INTO users (name, password) VALUES ('{username}', '{hashed}')"
    )
    conn.commit()
    return "Registered!"


# ------------------------------------------------------------------ #
# VULNERABILITY 9 – Open Redirect                                     #
# ------------------------------------------------------------------ #
@app.route("/redirect")
def open_redirect():
    target = request.args.get("next", "/")
    # Open redirect: no validation of redirect target
    return redirect(target)


if __name__ == "__main__":
    # Debug mode exposes interactive debugger to users
    app.run(debug=True, host="0.0.0.0", port=5000)

from flask import Flask, request

app = Flask(__name__)

# INTENTIONALLY VULNERABLE — for GuardPR AI demo only
@app.route("/login")
def login():
    email = request.args.get("email")
    password = request.args.get("password")
    import sqlite3

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL injection sink
    query = f"SELECT * FROM users WHERE email = '{email}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    return {"authenticated": bool(user)}


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # XSS sink
    return f"<html><body>Results for: {q}</body></html>"

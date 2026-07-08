"""
Intentionally Vulnerable Sample Application — for Remy e2e testing.

DO NOT deploy this code. It contains deliberate security vulnerabilities
designed to be detected by Remy's scanning engines.
"""

import os
import pickle
import subprocess
import random
import hashlib
import sqlite3
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

# [VULNERABILITY] Hardcoded API key — secrets scanner should catch this
STRIPE_KEY = "FAKE_STRIPE_API_KEY"
DB_PASSWORD = "supersecret123"

# [VULNERABILITY] Hardcoded AWS credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def get_db():
    return sqlite3.connect("app.db")


# [VULNERABILITY] SQL injection — string concatenation in execute()
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # SQLI
    return jsonify(cursor.fetchone())


# [VULNERABILITY] Missing authentication on sensitive route
@app.route("/admin/users")
def list_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    return jsonify(cursor.fetchall())


# [VULNERABILITY] Shell injection — subprocess with shell=True and user input
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    result = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True
    )  # Shell injection
    return result.stdout.decode()


# [VULNERABILITY] eval() with user input
@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    return str(eval(expr))  # RCE via eval


# [VULNERABILITY] pickle deserialization of user data
@app.route("/load", methods=["POST"])
def load_data():
    data = request.get_data()
    obj = pickle.loads(data)  # Insecure deserialization
    return str(obj)


# [VULNERABILITY] Weak random for security token
@app.route("/token")
def generate_token():
    token = str(random.randint(100000, 999999))  # Weak randomness for token
    return jsonify({"token": token})


# [VULNERABILITY] MD5 for password hashing
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # Weak hash


# [VULNERABILITY] yaml.load without SafeLoader
@app.route("/config", methods=["POST"])
def load_config():
    data = request.get_data().decode()
    config = yaml.load(data)  # Unsafe YAML load
    return jsonify(config)


# [VULNERABILITY] Auth bypass — client-controlled admin flag
@app.route("/secret")
def secret():
    is_admin = request.args.get("is_admin")  # Client-controlled admin
    if is_admin == "true":
        return jsonify({"secret": "top-secret-data"})
    return jsonify({"error": "forbidden"}), 403


# [VULNERABILITY] Hardcoded backdoor password
@app.route("/backdoor")
def backdoor():
    password = request.args.get("password")
    if password == "admin123":  # Hardcoded password
        return jsonify({"access": "granted"})
    return jsonify({"error": "forbidden"}), 403


# [VULNERABILITY] Missing rate limiting on auth endpoint
@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    pwd = data.get("password")
    conn = get_db()
    cursor = conn.cursor()
    # Also SQL injection here:
    cursor.execute(
        f"SELECT * FROM users WHERE username = '{username}' AND password = '{pwd}'"
    )
    user = cursor.fetchone()
    if user:
        return jsonify({"token": str(random.random())})  # Weak token
    return jsonify({"error": "invalid credentials"}), 401


# [VULNERABILITY] IDOR — no ownership check
@app.route("/document/<int:doc_id>")
def get_document(doc_id):
    conn = get_db()
    cursor = conn.cursor()
    # Missing: owner check. Any authenticated user can access any document.
    cursor.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
    return jsonify(cursor.fetchone())


# [VULNERABILITY] Broad except that silently swallows errors
def process_payment(amount, card):
    try:
        # Payment processing logic
        result = charge_card(card, amount)
        return result
    except Exception:
        pass  # Silently ignore all errors — very bad


def charge_card(card, amount):
    pass


if __name__ == "__main__":
    app.run(debug=True)  # Debug mode in production

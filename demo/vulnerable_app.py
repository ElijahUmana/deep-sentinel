"""
Demo vulnerable application for DeepSentinel security scanning.
Contains intentional vulnerabilities across multiple CWE categories.
DO NOT USE IN PRODUCTION — this is for demonstration only.
"""
import os
import sqlite3
import subprocess
import hashlib
import pickle
import yaml
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# CWE-798: Hardcoded credentials
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk-live-abcdef1234567890"
STRIPE_SECRET = "sk_live_51234567890abcdef"


# CWE-89: SQL Injection
@app.route("/api/users", methods=["GET"])
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABLE: String concatenation in SQL query
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    result = cursor.fetchone()
    return jsonify({"user": result})


# CWE-78: Command Injection
@app.route("/api/ping", methods=["POST"])
def ping_host():
    hostname = request.json.get("hostname")
    # VULNERABLE: User input passed directly to shell command
    result = subprocess.check_output(f"ping -c 1 {hostname}", shell=True)
    return jsonify({"result": result.decode()})


# CWE-79: Cross-Site Scripting
@app.route("/api/search")
def search():
    query = request.args.get("q", "")
    # VULNERABLE: Unescaped user input in HTML response
    return f"<html><body><h1>Results for: {query}</h1></body></html>"


# CWE-22: Path Traversal
@app.route("/api/files", methods=["GET"])
def read_file():
    filename = request.args.get("name")
    # VULNERABLE: No path validation — user can read any file
    with open(f"/app/uploads/{filename}", "r") as f:
        return jsonify({"content": f.read()})


# CWE-327: Weak Cryptography
@app.route("/api/auth/login", methods=["POST"])
def login():
    password = request.json.get("password")
    # VULNERABLE: MD5 is cryptographically broken
    hashed = hashlib.md5(password.encode()).hexdigest()
    return jsonify({"hash": hashed})


# CWE-502: Insecure Deserialization
@app.route("/api/import", methods=["POST"])
def import_data():
    data = request.get_data()
    # VULNERABLE: Deserializing untrusted pickle data
    obj = pickle.loads(data)
    return jsonify({"imported": str(obj)})


# CWE-918: Server-Side Request Forgery
@app.route("/api/fetch", methods=["POST"])
def fetch_url():
    url = request.json.get("url")
    # VULNERABLE: User-controlled URL with no validation
    response = requests.get(url)
    return jsonify({"status": response.status_code, "body": response.text[:1000]})


# CWE-400: No Rate Limiting on sensitive endpoint
@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    email = request.json.get("email")
    # VULNERABLE: No rate limiting on password reset
    # An attacker could enumerate emails or flood reset requests
    return jsonify({"message": f"Reset link sent to {email}"})


# CWE-209: Error Information Exposure
@app.route("/api/debug")
def debug_info():
    try:
        result = 1 / 0
    except Exception as e:
        # VULNERABLE: Full stack trace exposed to user
        import traceback
        return jsonify({
            "error": str(e),
            "traceback": traceback.format_exc(),
            "env": dict(os.environ)  # Leaks ALL environment variables
        })


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)

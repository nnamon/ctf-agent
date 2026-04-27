import os
from flask import Flask, request, send_from_directory, make_response, redirect
import jwt
import requests

app = Flask(__name__)

JWT_SECRET = os.environ["JWT_SECRET"]
FLAG_PATH = "/flag.txt"

LOGIN_HTML = """<!doctype html>
<html><head><title>Vault — Personal Notes</title></head><body>
<h1>Vault</h1>
<p>Your personal note vault. Log in to start.</p>
<form action="/login" method="POST">
  <input name="user" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <button>Login</button>
</form>
<p><small>Demo accounts: <code>guest / guest</code></small></p>
</body></html>
"""

ADMIN_HTML = """<!doctype html>
<html><head><title>Admin — Vault</title></head><body>
<h1>Welcome, admin.</h1>
<h2>URL Preview Tool</h2>
<p>Fetch a URL and preview the response.</p>
<form action="/preview" method="POST">
  <input name="url" placeholder="https://example.com" size="50">
  <button>Preview</button>
</form>
</body></html>
"""


@app.route("/")
def index():
    return LOGIN_HTML


@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("user", "")
    pw = request.form.get("password", "")
    if user == "guest" and pw == "guest":
        token = jwt.encode({"user": "guest", "admin": False}, JWT_SECRET, algorithm="HS256")
        resp = make_response("logged in. <a href='/dashboard'>dashboard</a>")
        resp.set_cookie("auth", token)
        return resp
    return "invalid credentials", 401


@app.route("/dashboard")
def dashboard():
    token = request.cookies.get("auth", "")
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return redirect("/")
    if data.get("admin"):
        return redirect("/admin")
    return f"<h1>Hello, {data.get('user', '?')}.</h1><p>Notes will be available in a future release.</p>"


@app.route("/admin")
def admin():
    token = request.cookies.get("auth", "")
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return "no auth", 401
    if not data.get("admin"):
        return "not admin", 403
    return ADMIN_HTML


@app.route("/preview", methods=["POST"])
def preview():
    token = request.cookies.get("auth", "")
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return "no auth", 401
    if not data.get("admin"):
        return "not admin", 403
    url = request.form.get("url", "")
    try:
        r = requests.get(url, timeout=5)
        return f"<pre>{r.text[:5000]}</pre>"
    except Exception as e:
        return f"error: {e}", 500


@app.route("/internal/flag")
def internal_flag():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return "forbidden — local only", 403
    with open(FLAG_PATH) as f:
        return f.read().strip()


@app.route("/.git/<path:p>")
def git_files(p):
    return send_from_directory("/var/www/.git", p)


@app.route("/.git/")
def git_root():
    return "<a href='HEAD'>HEAD</a> <a href='config'>config</a>"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

"""
ProgressJournal Tracker — backend server
• Serves tracker.html (protected) and login.html (public) on port 8090
• Auth: SQLite + bcrypt-style PBKDF2 password hashing, session cookies
• Proxies /api/chat to Groq (API key stays server-side)
"""

import os
import json
import sqlite3
import hashlib
import hmac
import secrets
import http.server
import urllib.request
import urllib.error
from urllib.parse import urlparse, parse_qs

# ── Config ────────────────────────────────────────────────────────────────────
GROQ_API_KEY  = os.environ.get("GROQ_API_KEY", "")
GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL    = "qwen/qwen3.8-27b"
PORT          = 8090
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
DB_PATH       = os.path.join(BASE_DIR, "data", "users.db")
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_hex(32))
SESSION_TTL   = 7 * 24 * 3600  # 7 days in seconds

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password TEXT NOT NULL,
                created  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token    TEXT PRIMARY KEY,
                user_id  INTEGER NOT NULL,
                expires  INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        conn.commit()
    print(f"[auth] DB ready at {DB_PATH}")

# ── Password hashing (PBKDF2-SHA256, no external deps) ───────────────────────
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"pbkdf2:sha256:260000:{salt}:{dk.hex()}"

def check_password(stored: str, password: str) -> bool:
    try:
        _, algo, iters, salt, dk_hex = stored.split(":")
        dk = hashlib.pbkdf2_hmac(algo, password.encode(), salt.encode(), int(iters))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False

# ── Session helpers ───────────────────────────────────────────────────────────
import time

def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = int(time.time()) + SESSION_TTL
    with get_db() as conn:
        # Cleanup expired sessions for this user
        conn.execute("DELETE FROM sessions WHERE user_id=? OR expires<?", (user_id, int(time.time())))
        conn.execute("INSERT INTO sessions (token, user_id, expires) VALUES (?,?,?)",
                     (token, user_id, expires))
        conn.commit()
    return token

def get_session_user(token: str):
    """Returns user row or None."""
    if not token:
        return None
    with get_db() as conn:
        row = conn.execute(
            "SELECT u.* FROM users u JOIN sessions s ON u.id=s.user_id "
            "WHERE s.token=? AND s.expires>?",
            (token, int(time.time()))
        ).fetchone()
    return row

def delete_session(token: str):
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()

def parse_session_cookie(cookie_header: str) -> str:
    """Extract session token from Cookie header."""
    if not cookie_header:
        return ""
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith("session="):
            return part[len("session="):]
    return ""

# ── HTML file helpers ─────────────────────────────────────────────────────────
def read_file(name: str) -> bytes:
    with open(os.path.join(BASE_DIR, name), "rb") as f:
        return f.read()

# ── HTTP Handler ──────────────────────────────────────────────────────────────
class TrackerHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"[tracker] {self.address_string()} {fmt % args}")

    # ── routing ──────────────────────────────────────────────────────────────
    def do_GET(self):
        path = urlparse(self.path).path
        token = parse_session_cookie(self.headers.get("Cookie", ""))
        user  = get_session_user(token)

        if path in ("/", "/index.html", "/tracker.html"):
            if not user:
                self._redirect("/login")
            else:
                self._serve_file("tracker.html", "text/html")

        elif path in ("/login", "/login.html"):
            if user:
                self._redirect("/")
            else:
                self._serve_file("login.html", "text/html")

        elif path == "/logout":
            delete_session(token)
            self._redirect_clear_cookie("/login")

        else:
            self._not_found()

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/auth/login":
            self._handle_login()
        elif path == "/api/auth/register":
            self._handle_register()
        elif path == "/api/chat":
            token = parse_session_cookie(self.headers.get("Cookie", ""))
            if not get_session_user(token):
                self._json_error(401, "Not authenticated")
            else:
                self._proxy_groq()
        else:
            self._not_found()

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    # ── auth endpoints ────────────────────────────────────────────────────────
    def _handle_login(self):
        body = self._read_json()
        if body is None:
            return
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        if not username or not password:
            self._json_error(400, "Username and password required")
            return
        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not user or not check_password(user["password"], password):
            self._json_error(401, "Invalid username or password")
            return
        token = create_session(user["id"])
        self._set_cookie_json(token, {"ok": True, "username": user["username"]})

    def _handle_register(self):
        body = self._read_json()
        if body is None:
            return
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        if not username or len(username) < 3:
            self._json_error(400, "Username must be at least 3 characters")
            return
        if len(password) < 6:
            self._json_error(400, "Password must be at least 6 characters")
            return
        hashed = hash_password(password)
        try:
            with get_db() as conn:
                conn.execute("INSERT INTO users (username, password) VALUES (?,?)",
                             (username, hashed))
                conn.commit()
                user_id = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
        except sqlite3.IntegrityError:
            self._json_error(409, "Username already taken")
            return
        token = create_session(user_id)
        self._set_cookie_json(token, {"ok": True, "username": username})

    # ── Groq proxy ────────────────────────────────────────────────────────────
    def _proxy_groq(self):
        if not GROQ_API_KEY:
            self._json_error(500, "GROQ_API_KEY not configured")
            return
        body = self._read_body()
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._json_error(400, "Invalid JSON")
            return

        payload["model"] = GROQ_MODEL
        # qwen/qwen3.8-27b: use json_object mode (not json_schema)
        if "response_format" in payload:
            payload["response_format"] = {"type": "json_object"}
            # Groq requires the word 'json' to appear in the messages when
            # using json_object mode — inject it into the system prompt if absent
            messages = payload.get("messages", [])
            full_text = " ".join(m.get("content", "") for m in messages).lower()
            if "json" not in full_text:
                for m in messages:
                    if m.get("role") == "system":
                        m["content"] = m["content"] + " Always respond with valid JSON."
                        break
                else:
                    # No system message — prepend one
                    messages.insert(0, {"role": "system", "content": "Always respond with valid JSON."})
            payload["messages"] = messages

        out = json.dumps(payload).encode()
        req = urllib.request.Request(
            GROQ_ENDPOINT, data=out,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "User-Agent": "Mozilla/5.0 (compatible; ProgressJournal/1.0)",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                resp_body = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", "application/json")
                self._cors_headers()
                self.end_headers()
                self.wfile.write(resp_body)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self._cors_headers()
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self._json_error(502, f"Groq error: {e}")

    # ── helpers ───────────────────────────────────────────────────────────────
    def _serve_file(self, name, content_type):
        try:
            content = read_file(name)
            self.send_response(200)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self._json_error(500, f"{name} not found")

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _redirect_clear_cookie(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Set-Cookie",
                         "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
        self.end_headers()

    def _set_cookie_json(self, token, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie",
                         f"session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}")
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        body = self._read_body()
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            self._json_error(400, "Invalid JSON body")
            return None

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length)

    def _json_error(self, code, message):
        body = json.dumps({"error": message}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _not_found(self):
        self._json_error(404, "Not found")

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), TrackerHandler)
    server.daemon_threads = True
    print(f"[tracker] Listening on http://0.0.0.0:{PORT}")
    print(f"[tracker] Groq key: {'configured' if GROQ_API_KEY else 'MISSING'}")
    print(f"[tracker] Model: {GROQ_MODEL}")
    server.serve_forever()

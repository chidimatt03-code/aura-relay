#!/usr/bin/env python3
"""AURA Zero-Knowledge Encrypted Relay Server (Python 3 stdlib + SQLite)."""
import base64, hashlib, json, os, re, sqlite3, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8787"))
DB_PATH = os.environ.get("AURA_DB", "aura_relay.db")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS msgs (id TEXT PRIMARY KEY, recipient TEXT, env TEXT, ts INTEGER)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rec ON msgs(recipient)")
    conn.execute("CREATE TABLE IF NOT EXISTS users (handle TEXT PRIMARY KEY, fp TEXT, card TEXT, ts INTEGER)")
    conn.execute("CREATE TABLE IF NOT EXISTS backups (id TEXT PRIMARY KEY, blob TEXT, ts INTEGER)")
    return conn

class Handler(BaseHTTPRequestHandler):
    def send_json(self, code, obj):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def verify_owner(self, target_fp):
        key_b64 = self.headers.get("x-nexa-key", "")
        ts = self.headers.get("x-nexa-ts", "")
        sig = self.headers.get("x-nexa-sig", "")
        if not (key_b64 and ts and sig):
            return False
        if abs(int(time.time() * 1000) - int(ts)) > 300_000:
            return False
        fp = hashlib.sha256(base64.b64decode(key_b64)).hexdigest()
        return fp.lower() == target_fp.lower()

    def do_GET(self):
        if self.path == "/health":
            return self.send_json(200, {"ok": True, "service": "aura-relay"})
        if self.path.startswith("/v1/inbox/"):
            fp = self.path.split("/v1/inbox/", 1)[1].strip()
            if not self.verify_owner(fp):
                return self.send_json(401, {"error": "unauthorized"})
            with db() as conn:
                rows = conn.execute("SELECT id, env FROM msgs WHERE recipient = ? ORDER BY ts ASC LIMIT 200", (fp,)).fetchall()
            return self.send_json(200, {"messages": [{"id": r[0], "env": r[1]} for r in rows]})
        if self.path.startswith("/v1/backup/"):
            bid = self.path.split("/v1/backup/", 1)[1].strip().lower()
            if not re.fullmatch(r"[0-9a-f]{64}", bid):
                return self.send_json(400, {"error": "bad_id"})
            with db() as conn:
                row = conn.execute("SELECT blob FROM backups WHERE id = ?", (bid,)).fetchone()
            if not row:
                return self.send_json(404, {"error": "not_found"})
            return self.send_json(200, {"blob": row[0]})
        if self.path.startswith("/v1/lookup/"):
            h = self.path.split("/v1/lookup/", 1)[1].strip().lower()
            with db() as conn:
                row = conn.execute("SELECT card FROM users WHERE handle = ?", (h,)).fetchone()
            if not row:
                return self.send_json(404, {"error": "not_found"})
            return self.send_json(200, {"handle": h, "card": row[0]})
        self.send_json(404, {"error": "not_found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 200000:
            return self.send_json(413, {"error": "too_large"})
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except Exception:
            return self.send_json(400, {"error": "bad_json"})
        if self.path == "/v1/send":
            to_fp = body.get("to", "").strip()
            msg_id = body.get("id", "").strip()
            env = body.get("env", "").strip()
            if not (to_fp and msg_id and env):
                return self.send_json(400, {"error": "missing_fields"})
            with db() as conn:
                conn.execute("INSERT OR IGNORE INTO msgs(id, recipient, env, ts) VALUES(?,?,?,?)",
                             (msg_id, to_fp, env, int(time.time())))
                conn.execute("DELETE FROM msgs WHERE ts < ?", (int(time.time()) - 7 * 86400,))
            return self.send_json(200, {"ok": True})
        if self.path == "/v1/backup":
            bid = str(body.get("id", "")).strip().lower()
            blob = str(body.get("blob", "")).strip()
            if not re.fullmatch(r"[0-9a-f]{64}", bid) or not blob or len(blob) > 150000:
                return self.send_json(400, {"error": "bad_backup"})
            with db() as conn:
                conn.execute("INSERT OR REPLACE INTO backups(id, blob, ts) VALUES(?,?,?)", (bid, blob, int(time.time())))
            return self.send_json(200, {"ok": True})
        if self.path == "/v1/register":
            h = str(body.get("handle", "")).strip().lower()
            fp = str(body.get("fp", "")).strip().lower()
            card = str(body.get("card", "")).strip()
            if not re.fullmatch(r"[a-z0-9]{1,12}-[0-9]{4}", h) or not re.fullmatch(r"[0-9a-f]{64}", fp):
                return self.send_json(400, {"error": "bad_handle"})
            if h[-4:] != "%04d" % (int(fp[:4], 16) % 10000):
                return self.send_json(400, {"error": "handle_mismatch"})
            if not card.startswith("NEXA1:") or len(card) > 4000:
                return self.send_json(400, {"error": "bad_card"})
            with db() as conn:
                row = conn.execute("SELECT fp, card FROM users WHERE handle = ?", (h,)).fetchone()
                if row:
                    if row[0] == fp and row[1] == card:
                        return self.send_json(200, {"ok": True})
                    return self.send_json(409, {"error": "handle_taken"})
                conn.execute("INSERT INTO users(handle, fp, card, ts) VALUES(?,?,?,?)", (h, fp, card, int(time.time())))
            return self.send_json(200, {"ok": True})
        if self.path == "/v1/ack":
            to_fp = body.get("to", "").strip()
            if not self.verify_owner(to_fp):
                return self.send_json(401, {"error": "unauthorized"})
            ids = body.get("ids", [])
            with db() as conn:
                for mid in ids:
                    conn.execute("DELETE FROM msgs WHERE recipient = ? AND id = ?", (to_fp, mid))
            return self.send_json(200, {"ok": True})
        self.send_json(404, {"error": "not_found"})

if __name__ == "__main__":
    print(f"AURA Zero-Knowledge Relay listening on 0.0.0.0:{PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

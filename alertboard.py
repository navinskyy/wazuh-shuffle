#!/usr/bin/env python3
"""AlertBoard - a tiny alert website for the Wazuh -> Shuffle lab.

Shuffle POSTs alerts to  http://<VM_IP>:8088/api/alerts
Open the dashboard at    http://<VM_IP>:8088/

Standard library only (works with the python3 that ships with Rocky 9).
Alerts are stored in SQLite next to this script (alertboard.db).
"""
import json
import os
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("ALERTBOARD_PORT", "8088"))
DB_PATH = os.environ.get(
    "ALERTBOARD_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "alertboard.db")
)
MAX_BODY = 2 * 1024 * 1024
db_lock = threading.Lock()


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db_lock, db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received TEXT NOT NULL,
                event_time TEXT,
                level INTEGER,
                rule_id TEXT,
                description TEXT,
                agent TEXT,
                srcip TEXT,
                srcuser TEXT,
                mitre TEXT,
                full_log TEXT,
                raw TEXT NOT NULL
            )"""
        )


def dig(obj, *path):
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def clean(value):
    """Drop empty values and Shuffle variables that were not substituted."""
    if value is None:
        return None
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    value = str(value).strip()
    if not value or value.startswith("$exec"):
        return None
    return value


def to_int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def extract(alert):
    """Accept the raw Wazuh/Shuffle payload ($exec) or a flat custom body."""
    full = alert.get("all_fields") if isinstance(alert.get("all_fields"), dict) else alert
    data = full.get("data") if isinstance(full.get("data"), dict) else {}
    return {
        "event_time": clean(full.get("timestamp") or alert.get("timestamp")),
        "level": to_int(dig(full, "rule", "level") or alert.get("level") or alert.get("severity")),
        "rule_id": clean(dig(full, "rule", "id") or alert.get("rule_id")),
        "description": clean(
            dig(full, "rule", "description") or alert.get("title") or alert.get("description")
        ),
        "agent": clean(dig(full, "agent", "name") or alert.get("agent")),
        "srcip": clean(data.get("srcip") or alert.get("srcip")),
        "srcuser": clean(data.get("srcuser") or data.get("dstuser") or alert.get("srcuser")),
        "mitre": clean(dig(full, "rule", "mitre", "id") or alert.get("mitre")),
        "full_log": clean(full.get("full_log") or alert.get("text")),
    }


def save(alert):
    fields = extract(alert)
    with db_lock, db() as conn:
        cur = conn.execute(
            """INSERT INTO alerts (received, event_time, level, rule_id, description, agent,
               srcip, srcuser, mitre, full_log, raw)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                fields["event_time"],
                fields["level"],
                fields["rule_id"],
                fields["description"],
                fields["agent"],
                fields["srcip"],
                fields["srcuser"],
                fields["mitre"],
                fields["full_log"],
                json.dumps(alert),
            ),
        )
        return cur.lastrowid


def list_alerts(limit=500):
    with db_lock, db() as conn:
        rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


class Handler(BaseHTTPRequestHandler):
    server_version = "AlertBoard/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def send(self, code, body, ctype="application/json"):
        payload = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/":
            self.send(200, PAGE, "text/html")
        elif url.path == "/api/alerts":
            limit = to_int(parse_qs(url.query).get("limit", ["500"])[0]) or 500
            self.send(200, json.dumps(list_alerts(min(limit, 5000))))
        elif url.path == "/health":
            self.send(200, '{"ok": true}')
        else:
            self.send(404, '{"error": "not found"}')

    def do_POST(self):
        if urlparse(self.path).path != "/api/alerts":
            self.send(404, '{"error": "not found"}')
            return
        length = to_int(self.headers.get("Content-Length")) or 0
        if length <= 0 or length > MAX_BODY:
            self.send(400, '{"error": "empty or too large body"}')
            return
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw)
        except ValueError:
            body = {"text": raw.decode(errors="replace")}
        alerts = body if isinstance(body, list) else [body]
        ids = [save(a if isinstance(a, dict) else {"text": str(a)}) for a in alerts]
        self.send(201, json.dumps({"success": True, "ids": ids}))

    def do_DELETE(self):
        if urlparse(self.path).path != "/api/alerts":
            self.send(404, '{"error": "not found"}')
            return
        with db_lock, db() as conn:
            conn.execute("DELETE FROM alerts")
        self.send(200, '{"success": true}')


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AlertBoard</title>
<style>
  :root {
    --bg: #0f1419; --panel: #171e26; --line: #263240; --text: #e6edf3; --muted: #8b98a5;
    --crit: #ff5d5d; --high: #ff9f43; --med: #f5c542; --low: #4fb3ff; --ok: #3fd68f;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
         font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  header { display: flex; align-items: center; gap: 12px; padding: 16px 24px;
           border-bottom: 1px solid var(--line); flex-wrap: wrap; }
  header h1 { font-size: 18px; margin: 0; letter-spacing: .3px; }
  .live { display: inline-flex; align-items: center; gap: 6px; color: var(--muted); font-size: 12px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--ok); }
  .dot.off { background: var(--crit); }
  .spacer { flex: 1; }
  main { padding: 20px 24px; max-width: 1400px; margin: 0 auto; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px;
          cursor: pointer; transition: border-color .15s; }
  .card:hover, .card.active { border-color: var(--muted); }
  .card .n { font-size: 30px; font-weight: 650; font-variant-numeric: tabular-nums; }
  .card .l { color: var(--muted); font-size: 12px; }
  .toolbar { display: flex; gap: 10px; margin: 20px 0 12px; flex-wrap: wrap; }
  input, button { background: var(--panel); color: var(--text); border: 1px solid var(--line);
                  border-radius: 8px; padding: 8px 12px; font: inherit; }
  input { flex: 1; min-width: 200px; }
  button { cursor: pointer; }
  button:hover { border-color: var(--muted); }
  .wrap { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--line); white-space: nowrap; }
  th { color: var(--muted); font-weight: 500; font-size: 12px; text-transform: uppercase; letter-spacing: .5px; }
  td.desc { white-space: normal; min-width: 260px; }
  tr.row { cursor: pointer; }
  tr.row:hover td { background: #1c2530; }
  tr.new td { animation: flash 2s ease-out; }
  @keyframes flash { from { background: #2a3a1f; } to { background: transparent; } }
  .sev { display: inline-block; min-width: 34px; text-align: center; padding: 2px 8px; border-radius: 999px;
         font-weight: 650; font-size: 12px; color: #111; }
  .crit { background: var(--crit); } .high { background: var(--high); }
  .med { background: var(--med); } .low { background: var(--low); }
  .mono { font-family: ui-monospace, Consolas, monospace; font-size: 12.5px; }
  .muted { color: var(--muted); }
  pre { margin: 0; padding: 14px; background: #0b1015; border-radius: 8px; overflow: auto; max-height: 420px;
        font-size: 12px; white-space: pre-wrap; word-break: break-word; }
  .empty { padding: 40px; text-align: center; color: var(--muted); }
</style>
</head>
<body>
<header>
  <h1>AlertBoard</h1>
  <span class="live"><span class="dot" id="dot"></span><span id="status">connecting...</span></span>
  <span class="spacer"></span>
  <span class="muted" id="updated"></span>
</header>
<main>
  <div class="cards">
    <div class="card active" data-sev="all"><div class="n" id="c-all">0</div><div class="l">All alerts</div></div>
    <div class="card" data-sev="crit"><div class="n" style="color:var(--crit)" id="c-crit">0</div><div class="l">Critical (15+)</div></div>
    <div class="card" data-sev="high"><div class="n" style="color:var(--high)" id="c-high">0</div><div class="l">High (12-14)</div></div>
    <div class="card" data-sev="med"><div class="n" style="color:var(--med)" id="c-med">0</div><div class="l">Medium (7-11)</div></div>
    <div class="card" data-sev="low"><div class="n" style="color:var(--low)" id="c-low">0</div><div class="l">Low (0-6)</div></div>
  </div>
  <div class="toolbar">
    <input id="q" placeholder="Search rule, agent, IP, user...">
    <button id="clear">Clear all</button>
  </div>
  <div class="wrap">
    <table>
      <thead><tr><th>Received</th><th>Level</th><th>Rule</th><th>Description</th><th>Agent</th><th>Source IP</th><th>User</th><th>MITRE</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
    <div class="empty" id="empty">No alerts yet. Waiting for Shuffle...</div>
  </div>
</main>
<script>
let alerts = [], sevFilter = "all", openId = null, lastMaxId = 0;

function sevOf(level) {
  if (level == null) return "low";
  if (level >= 15) return "crit";
  if (level >= 12) return "high";
  if (level >= 7) return "med";
  return "low";
}
function cell(tr, text, cls) {
  const td = document.createElement("td");
  td.textContent = text == null || text === "" ? "-" : text;
  if (cls) td.className = cls;
  tr.appendChild(td);
  return td;
}
function fmtTime(iso) {
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString();
}
function render(newIds) {
  const q = document.getElementById("q").value.trim().toLowerCase();
  const counts = { all: alerts.length, crit: 0, high: 0, med: 0, low: 0 };
  alerts.forEach(a => counts[sevOf(a.level)]++);
  for (const k in counts) document.getElementById("c-" + k).textContent = counts[k];

  const shown = alerts.filter(a =>
    (sevFilter === "all" || sevOf(a.level) === sevFilter) &&
    (!q || [a.rule_id, a.description, a.agent, a.srcip, a.srcuser, a.mitre, a.full_log]
            .some(v => v && String(v).toLowerCase().includes(q))));

  const body = document.getElementById("rows");
  body.replaceChildren();
  shown.forEach(a => {
    const tr = document.createElement("tr");
    tr.className = "row" + (newIds.has(a.id) ? " new" : "");
    cell(tr, fmtTime(a.received), "muted");
    const lv = cell(tr, "");
    const pill = document.createElement("span");
    pill.className = "sev " + sevOf(a.level);
    pill.textContent = a.level == null ? "?" : a.level;
    lv.replaceChildren(pill);
    cell(tr, a.rule_id, "mono");
    cell(tr, a.description, "desc");
    cell(tr, a.agent);
    cell(tr, a.srcip, "mono");
    cell(tr, a.srcuser);
    cell(tr, a.mitre, "mono");
    tr.onclick = () => { openId = openId === a.id ? null : a.id; render(new Set()); };
    body.appendChild(tr);
    if (openId === a.id) {
      const d = document.createElement("tr"), td = document.createElement("td");
      td.colSpan = 8;
      const pre = document.createElement("pre");
      let raw = a.raw;
      try { raw = JSON.stringify(JSON.parse(a.raw), null, 2); } catch (e) {}
      pre.textContent = (a.full_log ? "full_log: " + a.full_log + "\n\n" : "") + raw;
      td.appendChild(pre); d.appendChild(td); body.appendChild(d);
    }
  });
  document.getElementById("empty").style.display = shown.length ? "none" : "block";
}
async function load() {
  try {
    const res = await fetch("/api/alerts?limit=1000", { cache: "no-store" });
    const data = await res.json();
    const newIds = new Set(lastMaxId ? data.filter(a => a.id > lastMaxId).map(a => a.id) : []);
    lastMaxId = data.reduce((m, a) => Math.max(m, a.id), lastMaxId);
    alerts = data;
    render(newIds);
    document.getElementById("dot").className = "dot";
    document.getElementById("status").textContent = "live";
    document.getElementById("updated").textContent = "updated " + new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById("dot").className = "dot off";
    document.getElementById("status").textContent = "disconnected";
  }
}
document.querySelectorAll(".card").forEach(c => c.onclick = () => {
  document.querySelectorAll(".card").forEach(x => x.classList.remove("active"));
  c.classList.add("active"); sevFilter = c.dataset.sev; render(new Set());
});
document.getElementById("q").oninput = () => render(new Set());
document.getElementById("clear").onclick = async () => {
  if (!confirm("Delete all alerts from AlertBoard?")) return;
  await fetch("/api/alerts", { method: "DELETE" }); lastMaxId = 0; load();
};
load();
setInterval(load, 5000);
</script>
</body>
</html>
"""


if __name__ == "__main__":
    init_db()
    print("AlertBoard listening on 0.0.0.0:%d (db: %s)" % (PORT, DB_PATH))
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

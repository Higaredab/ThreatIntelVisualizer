from flask import Flask, request, render_template, jsonify, make_response
import requests
import sqlite3
import os
import csv
import socket
import time
import json
import ast
from io import StringIO
from dotenv import load_dotenv

# === Load settings & API keys from .env ===
load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in ("1", "true", "yes")

app = Flask(__name__)

# === SQLite helpers ===
DB_PATH = "indicators.db"

def get_db():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS indicators (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               domain TEXT,
               pulse_info TEXT
           )"""
    )
    conn.commit()
    conn.close()

init_db()

# === Safe JSON load of stored pulse_info (backward-compatible with old rows) ===
def load_pulse_info(s: str):
    if s is None:
        return {}
    # Prefer JSON
    try:
        return json.loads(s)
    except Exception:
        pass
    # Fallback to old Python-literal strings (safer than eval)
    try:
        return ast.literal_eval(s)
    except Exception:
        return {}

# === Demo data helpers ===
def load_demo_rows():
    """
    Expected format for each row:
    { "domain": "example.com", "pulse_info": {"count": 3, "pulses":[{"name":"...","description":"..."}, ...]} }
    """
    demo_path = os.path.join(os.path.dirname(__file__), "demo_scans.json")
    if os.path.exists(demo_path):
        with open(demo_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # if file is a simpler format, adapt it:
            norm = []
            for row in data:
                if "pulse_info" in row:
                    norm.append(row)
                else:
                    # Accept {domain,severity,pulse_count}
                    pc = int(row.get("pulse_count", 0))
                    norm.append({
                        "domain": row.get("domain", "(unknown)"),
                        "pulse_info": {"count": pc, "pulses": [{"name": f"Demo pulse {i+1}", "description": ""} for i in range(pc)]}
                    })
            return norm

    # Built-in minimal fallback
    return [
        {"domain": "contoso.com", "pulse_info": {"count": 5, "pulses": [{"name": f"Pulse {i+1}", "description": ""} for i in range(5)]}},
        {"domain": "fabrikam.net", "pulse_info": {"count": 2, "pulses": [{"name": f"Pulse {i+1}", "description": ""} for i in range(2)]}},
        {"domain": "tailspindev.io", "pulse_info": {"count": 1, "pulses": [{"name": "Pulse 1", "description": ""}]}},
        {"domain": "adatum.org", "pulse_info": {"count": 7, "pulses": [{"name": f"Pulse {i+1}", "description": ""} for i in range(7)]}},
        {"domain": "northwind.example", "pulse_info": {"count": 3, "pulses": [{"name": f"Pulse {i+1}", "description": ""} for i in range(3)]}},
    ]

# === Home Page ===
@app.route('/')
def index():
    return render_template('index.html', demo_mode=DEMO_MODE)

# === SCAN Route ===
@app.route('/scan', methods=['POST'])
def scan():
    domain = request.form.get('domain')
    if not domain:
        return render_template('index.html', error="Please enter a domain.", demo_mode=DEMO_MODE)

    # --- Demo path: NO external API calls ---
    if DEMO_MODE:
        pulse_info = {
            "count": 3,
            "pulses": [
                {"name": "Demo Threat Intel 1", "description": "Sample OTX pulse (demo)"},
                {"name": "Demo Threat Intel 2", "description": "Sample OTX pulse (demo)"},
                {"name": "Demo Threat Intel 3", "description": "Sample OTX pulse (demo)"}
            ]
        }
        vt_data = {"reputation": 0, "last_analysis_stats": {"malicious": 0, "suspicious": 1, "harmless": 70}}
        abuse_data = {"abuseConfidenceScore": 15}
    else:
        # ===== OTX =====
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        otx_headers = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}
        otx_response = requests.get(otx_url, headers=otx_headers)
        pulse_info = otx_response.json().get("pulse_info", {}) if otx_response.status_code == 200 else {}
        time.sleep(0.5)  # Respect API rate limits

        # ===== VirusTotal =====
        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        vt_headers = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}
        vt_response = requests.get(vt_url, headers=vt_headers)
        vt_data = vt_response.json().get("data", {}).get("attributes", {}) if vt_response.status_code == 200 else {}
        time.sleep(0.5)

        # ===== AbuseIPDB =====
        abuse_data = {}
        try:
            ip = socket.gethostbyname(domain)
            abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
            abuse_headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"} if ABUSEIPDB_API_KEY else {"Accept": "application/json"}
            abuse_response = requests.get(abuse_url, headers=abuse_headers)
            if abuse_response.status_code == 200:
                abuse_data = abuse_response.json().get("data", {})
        except Exception as e:
            print(f"[!] Error querying AbuseIPDB: {e}")

    # Save to DB (store as JSON, not str(dict))
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO indicators (domain, pulse_info) VALUES (?, ?)", (domain, json.dumps(pulse_info)))
        conn.commit()
    finally:
        conn.close()

    return render_template(
        'result.html',
        domain=domain,
        pulse_info=pulse_info,
        vt_data=vt_data,
        abuse_data=abuse_data,
        demo_mode=DEMO_MODE
    )

# === HISTORY Route ===
@app.route('/history')
def history():
    query = request.args.get('query', '')
    conn = get_db()
    c = conn.cursor()
    if query:
        c.execute("SELECT domain, pulse_info FROM indicators WHERE domain LIKE ? ORDER BY id DESC", (f"%{query}%",))
    else:
        c.execute("SELECT domain, pulse_info FROM indicators ORDER BY id DESC")
    results = c.fetchall()
    conn.close()

    history_data = []
    for domain, pulse_info_s in results:
        pulse_dict = load_pulse_info(pulse_info_s)
        history_data.append({
            "domain": domain,
            "pulses": pulse_dict.get("pulses", [])
        })

    return render_template('history.html', history=history_data, query=query, demo_mode=DEMO_MODE)

# === API for Visualize page (Chart.js fetches this) ===
@app.route('/api/visualize-data')
def visualize_data():
    # Build pulses-per-domain (top N)
    def aggregate(rows, limit=20):
        items = []
        for d, pi in rows:
            info = load_pulse_info(pi)
            count = len(info.get("pulses", []))
            items.append({"domain": d, "pulses": count})
        # collapse duplicates if same domain appears multiple times
        agg = {}
        for it in items:
            agg[it["domain"]] = agg.get(it["domain"], 0) + it["pulses"]
        sorted_items = sorted(
            [{"domain": k, "pulses": v} for k, v in agg.items()],
            key=lambda x: -x["pulses"]
        )
        return sorted_items[:limit]

    if DEMO_MODE:
        demo_rows = [(row["domain"], json.dumps(row["pulse_info"])) for row in load_demo_rows()]
        data = aggregate(demo_rows)
        return jsonify({"mode": "demo", "pulses_per_domain": data})

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT domain, pulse_info FROM indicators")
    rows = c.fetchall()
    conn.close()
    data = aggregate(rows)
    return jsonify({"mode": "live", "pulses_per_domain": data})

# === VISUALIZE Route ===
@app.route('/visualize')
def visualize():
    # Template is simple; Chart.js will call /api/visualize-data
    return render_template('visualize.html', demo_mode=DEMO_MODE)

# === EXPORT CSV Route ===
@app.route('/export_csv/<domain>')
def export_csv(domain):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT pulse_info FROM indicators WHERE domain = ? ORDER BY id DESC LIMIT 1", (domain,))
    row = c.fetchone()
    conn.close()

    if not row:
        return "No data found for this domain", 404

    pulse_info = load_pulse_info(row[0])
    pulses = pulse_info.get("pulses", [])

    # Build CSV in-memory
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(["Pulse Name", "Description"])
    for pulse in pulses:
        writer.writerow([pulse.get("name", ""), pulse.get("description", "")])

    response = make_response(si.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename={domain}_pulses.csv"
    response.headers["Content-type"] = "text/csv"
    return response

# === RUN APP ===
if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, request, render_template, jsonify, make_response
import requests
import sqlite3
import os
import csv
import socket
import time
from dotenv import load_dotenv

# Load API keys from .env
load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

app = Flask(__name__)

# === Initialize SQLite DB ===
def init_db():
    conn = sqlite3.connect('indicators.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT,
                    pulse_info TEXT
                )''')
    conn.commit()
    conn.close()

init_db()

# === Home Page ===
@app.route('/')
def index():
    return render_template('index.html')

# === SCAN Route ===
@app.route('/scan', methods=['POST'])
def scan():
    import socket
    import time  # ✅ ADDED to support sleep for rate limits

    domain = request.form.get('domain')
    #print("🔍 Domain received:", domain)  # ✅ DEBUG

    if not domain:
        return render_template('index.html', error="Please enter a domain.")

    # ===== OTX =====
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    otx_headers = {"X-OTX-API-KEY": OTX_API_KEY}
    otx_response = requests.get(otx_url, headers=otx_headers)
    pulse_info = otx_response.json().get("pulse_info", {}) if otx_response.status_code == 200 else {}
    ##print("📡 OTX pulse_info summary:", pulse_info.get("count", "No count"))  # ✅ DEBUG

    time.sleep(0.5)  # ✅ Respect API rate limits

    # ===== VirusTotal =====
    vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    vt_headers = {"x-apikey": VT_API_KEY}
    vt_response = requests.get(vt_url, headers=vt_headers)
    vt_data = vt_response.json().get("data", {}).get("attributes", {}) if vt_response.status_code == 200 else {}
    ##print("🦠 VT reputation:", vt_data.get("reputation", "N/A"))  # ✅ DEBUG

    time.sleep(0.5)

    # ===== AbuseIPDB =====
    abuse_data = {}
    try:
        ip = socket.gethostbyname(domain)
        abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        abuse_headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        abuse_response = requests.get(abuse_url, headers=abuse_headers)
        if abuse_response.status_code == 200:
            abuse_data = abuse_response.json().get("data", {})
    except Exception as e:
        print(f"[!] Error querying AbuseIPDB: {e}")

    ##print("🚨 Abuse Confidence Score:", abuse_data.get("abuseConfidenceScore", "N/A"))  # ✅ DEBUG

    # Save to DB
    conn = sqlite3.connect('indicators.db')
    c = conn.cursor()
    c.execute("INSERT INTO indicators (domain, pulse_info) VALUES (?, ?)", (domain, str(pulse_info)))
    conn.commit()
    conn.close()

    return render_template(
        'result.html',
        domain=domain,
        pulse_info=pulse_info,
        vt_data=vt_data,
        abuse_data=abuse_data
    )

# === HISTORY Route ===
@app.route('/history')
def history():
    query = request.args.get('query', '')
    conn = sqlite3.connect('indicators.db')
    c = conn.cursor()
    if query:
        c.execute("SELECT domain, pulse_info FROM indicators WHERE domain LIKE ? ORDER BY id DESC", (f"%{query}%",))
    else:
        c.execute("SELECT domain, pulse_info FROM indicators ORDER BY id DESC")
    results = c.fetchall()
    conn.close()

    history_data = []
    for domain, pulse_info in results:
        try:
            pulse_dict = eval(pulse_info)
            history_data.append({
                "domain": domain,
                "pulses": pulse_dict.get("pulses", [])
            })
        except Exception as e:
            print(f"Error parsing pulse_info for {domain}: {e}")

    return render_template('history.html', history=history_data, query=query)

# === VISUALIZE Route ===
@app.route('/visualize')
def visualize():
    conn = sqlite3.connect('indicators.db')
    c = conn.cursor()
    c.execute("SELECT domain, pulse_info FROM indicators")
    results = c.fetchall()
    conn.close()

    chart_data = {}
    for domain, pulse_info in results:
        try:
            pulse_dict = eval(pulse_info)
            count = len(pulse_dict.get("pulses", []))
            chart_data[domain] = chart_data.get(domain, 0) + count
        except Exception as e:
            print(f"Error parsing pulse_info for {domain}: {e}")

    return render_template('visualize.html', domains=list(chart_data.keys()), counts=list(chart_data.values()))

# === EXPORT CSV Route ===
@app.route('/export_csv/<domain>')
def export_csv(domain):
    conn = sqlite3.connect('indicators.db')
    c = conn.cursor()
    c.execute("SELECT pulse_info FROM indicators WHERE domain = ? ORDER BY id DESC LIMIT 1", (domain,))
    row = c.fetchone()
    conn.close()

    if not row:
        return "No data found for this domain", 404

    try:
        pulse_info = eval(row[0])
        pulses = pulse_info.get("pulses", [])
    except Exception as e:
        return f"Error parsing data: {e}", 500

    output = [[pulse.get("name", ""), pulse.get("description", "")] for pulse in pulses]

    response = make_response()
    writer = csv.writer(response)
    writer.writerow(["Pulse Name", "Description"])
    writer.writerows(output)
    response.headers["Content-Disposition"] = f"attachment; filename={domain}_pulses.csv"
    response.headers["Content-type"] = "text/csv"
    return response

# === RUN APP ===
if __name__ == '__main__':
    app.run(debug=True)

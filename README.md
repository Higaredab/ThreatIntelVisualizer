ThreatIntelVisualizer
 Professional Summary

The ThreatIntelVisualizer project was built as part of my cybersecurity engineering portfolio to demonstrate how real-world threat intelligence can be integrated into a working security tool. By combining data from AlienVault OTX, VirusTotal, and AbuseIPDB, I designed a Flask-based backend API that fetches, analyzes, and securely stores intelligence on domains and IPs in a SQLite database for further inspection.

This repository highlights my ability to:

Build and secure APIs

Integrate multiple cybersecurity intelligence feeds

Implement defensive coding, error handling, and secure environment variable management

Apply professional software engineering practices (Git, GitHub, documentation, and clean architecture)

This project is intended to showcase my hands-on security engineering skills to recruiters and hiring managers.

PURPOSE

The Threat Intel Visualizer helps users determine whether a domain (e.g., phishing.com) or IP address is associated with known malicious activity by querying multiple sources:

AlienVault OTX – Open Threat Exchange platform

VirusTotal – Aggregated malware detection and reputation data

AbuseIPDB – Community-driven IP reputation database

Skills Learned

Building and securing a Flask REST API

Querying and parsing threat intel data from multiple APIs

Writing structured results to a local SQLite database

Using environment variables securely via .env

Defensive coding & structured error handling

Version control and collaboration with Git/GitHub


Tools & Technologies

Flask (Python micro web framework)

AlienVault OTX API (Open Threat Exchange)

VirusTotal API (domain/file reputation)

AbuseIPDB API (IP abuse reports)

SQLite3 (lightweight embedded database)

Requests (Python HTTP library)

dotenv (environment variable management)

Visual Studio Code + GitHub (development & version control)

⚙ Project Setup
Environment Setup
git clone https://github.com/<your-username>/ThreatIntelVisualizer.git
cd ThreatIntelVisualizer
python -m venv venv
venv\Scripts\activate   # (Windows)
pip install -r requirements.txt

2. Create .env file
OTX_API_KEY=your_otx_key_here
VT_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here

3. RUN FLASK API
   python. app.py

4. EXAMPLE REQUEST
   http://127.0.0.1:5000/scan?domain=example.com

  Sample Response
  {
  "indicator": "example.com",
  "otx": { "pulse_count": 5, "tags": [...] },
  "virustotal": { "malicious_votes": 3, "harmless_votes": 57 },
  "abuseipdb": { "totalReports": 12, "abuseConfidenceScore": 90 }
}

Database 
SQLITE table:
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    otx_data TEXT,
    vt_data TEXT,
    abuseipdb_data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

DEFENSIVE FEATURES
.env and secrets excluded via .gitignore

Structured JSON error responses for API failures

Prevents duplicate entries unless results are valid

Clear logging for debugging

Future Improvements

Interactive dashboard with Plotly/Dash or React frontend

Support for IPs, file hashes, and URLs as inputs

Correlation of recurring indicators over time

ML clustering of similar threats

Automated alerts (Slack/Email) for malicious hits

Case Study Example

Scanned example.com:

Flagged as associated with phishing activity (via OTX & AbuseIPDB)

VirusTotal showed mixed reputation

Result stored locally in SQLite for reporting

Conclusion

This project showcases:

API integration skills (OTX, VirusTotal, AbuseIPDB)

Backend development with Flask

Database design and secure storage

Practical SOC workflows for cyber threat intelligence

It serves as a strong foundation for building more advanced cybersecurity automation and visualization platforms.

Demo

























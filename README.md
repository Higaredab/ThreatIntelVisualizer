# ThreatIntelVisualizer

The ThreatIntelVisualizer project was built to demonstrate how publicly available threat intelligence data can be fetched, analyzed, and stored securely for further inspection. The goal was to leverage AlienVault’s OTX API, build a Flask-based backend, and store results using SQLite for later correlation and analysis.


Skills Learned

- Building and securing a Flask REST API
- Querying and parsing threat intel data using public APIs
- Writing structured data to a local SQLite database
- Using environment variables securely via `.env`
- Implementing defensive coding and error handling
- Using Git and GitHub for version control and collaboration

## Tools Used

- Flask (Python micro web framework)
- AlienVault Open Threat Exchange (OTX) API
- SQLite3 (lightweight embedded database)
- Python `requests` for HTTP calls
- `dotenv` for environment variable management
- Visual Studio Code & GitHub for development

---

## Steps

### 1. Setup & API Integration

- Created project structure with virtual environment
- Registered and securely stored OTX API key in a `.env` file
- Built a `/scan?domain=example.com` endpoint to pull threat data

```bash
http://127.0.0.1:5000/scan?domain=example.com

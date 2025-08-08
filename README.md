# ThreatIntelVisualizer

The ThreatIntelVisualizer project was built to demonstrate how publicly available threat intelligence data can be fetched, analyzed, and stored securely for further inspection. The goal was to leverage AlienVault’s OTX API, build a Flask-based backend, and store results using SQLite for later correlation and analysis.

Purpose 
The Threat Intel Visualizer helps users determine whether a domain (e.g., phishing.com) is associated with known malicious activity by querying the AlienVault OTX (Open Threat Exchange) platform.

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

{
  "indicator": "example.com",
  "pulse_info": {
    "count": 5,
    "pulses": [...]
  }
}


2. Secure Data Storage

    Created a local SQLite database with indicators table:

    CREATE TABLE IF NOT EXISTS indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT,
        pulse_info TEXT
    );

    Data was inserted only when valid results were returned.

3. Debugging & Error Handling

    Ensured:

        .env file is ignored using .gitignore

        Errors like missing domain or API failures return structured error responses

        Table mismatches were debugged and resolved with table schema updates

Proactive Threat Intelligence Concepts (Future Ideas)

    Add visualization using tools like Plotly, Dash, or a React frontend

    Correlate indicators over time to detect recurring domains or IPs

    Add support for IP, file hash, and URL-based IOCs

    Explore ML models to cluster similar threat patterns

Case Study: example.com

    Ran a threat intel lookup on example.com

    Observed pulse info associated with phishing behavior

    Stored result locally for potential use in reporting or alerting logic

Conclusion

This project served as a gateway into the world of cyber threat intelligence. By combining Python, public APIs, and data handling, I created a tool that could be extended into a more complex analysis engine. I now better understand the processes behind:

    Automated threat ingestion

    Lightweight data storage

    And using code to power modern SOC workflows.

Future development will focus on dashboards, enrichment from additional sources, and alerting logic.

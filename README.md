# 🛡️ CyberShield Analyzer

A local-first security log analytics dashboard for investigating authentication failures, suspicious IP activity, and traffic spikes.

## Highlights
- Upload CSV security logs or use bundled synthetic demo events
- Detect brute-force patterns and unusually high request volumes with transparent, configurable rules
- Explore timeline charts, source IP statistics, and flagged findings
- Export findings as CSV
- Privacy-first: no external threat intelligence service or API key required
- Automated tests for detection logic

## Run locally
```bash
git clone https://github.com/iamAdarshAnand/CyberShield-Analyzer.git
cd CyberShield-Analyzer
python -m venv .venv
source .venv/bin/activate # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Input schema
CSV must contain `timestamp`, `source_ip`, `event_type`, `status`.
- timestamp: ISO 8601 or other pandas-parsable datetime
- source_ip: string (IPv4/IPv6 accepted as labels)
- event_type: e.g. `login`, `request`
- status: `failure`, `success`, or other value

Example:
```csv
timestamp,source_ip,event_type,status
2026-01-01T10:00:00Z,192.0.2.10,login,failure
2026-01-01T10:00:20Z,192.0.2.10,login,failure
2026-01-01T10:01:00Z,198.51.100.5,request,success
```

## Detection rules
- Brute-force indicator: at least N failed login attempts per IP within a rolling window
- Volume spike indicator: at least N total events per IP within a rolling window
- Alerts are heuristic indicators, **not proof of compromise**. Review source logs and context before acting.

## Test
```bash
pytest -q
```

## Security and privacy
Use only logs you are authorized to analyze. Avoid uploading secrets or personal data to third-party hosting. No attack or exploitation features are included.

Created by Adarsh Anand.

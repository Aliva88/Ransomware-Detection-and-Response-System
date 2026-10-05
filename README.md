\# RansomShield



\### Ransomware Detection and Response System



RansomShield is a Windows-based ransomware detection and response system that monitors file activity, detects ransomware-like behavior, calculates threat severity, creates security incidents, and provides a professional SOC-style dashboard.



\## Features



\- Real-time Windows file monitoring

\- File modification detection

\- Mass file rename detection

\- File extension change detection

\- Entropy-based detection

\- Sliding-window behavioral detection

\- Process activity monitoring

\- Threat scoring and severity classification

\- Automatic ransomware incident creation

\- Incident threat score and behavior-signal storage

\- System registration and verification

\- Protection start/stop

\- SOC security dashboard

\- Attack Replay

\- JSON and CSV security reports

\- SQLite database

\- FastAPI backend

\- Automated test suite



\## Detection Workflow



Windows System

→ File Monitoring

→ Detection Engine

→ Behavioral Analysis

→ Threat Scoring

→ Threat Level

→ Incident Creation

→ Incident Response

→ SOC Dashboard / Reports



\## Threat Levels



| Score | Level |

|---:|---|

| 0–29 | Low |

| 30–59 | Medium |

| 60–79 | High |

| 80–100 | Critical |



\## Technology Stack



\- Python

\- FastAPI

\- SQLAlchemy

\- SQLite

\- Watchdog

\- psutil

\- PyYAML

\- Pytest

\- HTML / CSS / JavaScript



\## Run the Project



Activate the virtual environment:



.\\.venv\\Scripts\\Activate.ps1



Start the server:



uvicorn app.main:app --host 127.0.0.1 --port 8001



Open:



http://127.0.0.1:8001



API documentation:



http://127.0.0.1:8001/docs



\## Useful APIs



GET /api/health

GET /api/status

GET /api/threat

GET /api/incidents

GET /api/dashboard

GET /api/reports/json

GET /api/reports/csv

GET /api/attack-replay



\## Testing



Run the complete test suite:



pytest -q



Verified test result:



14 passed



\## Project Status



RansomShield v1.0 implementation is complete, including real Windows monitoring, ransomware behavioral detection, threat scoring, incident response, SOC dashboard, Attack Replay, reporting, and automated testing.


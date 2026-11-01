<<<<<<< HEAD
# 🛡️ Cybersecurity AI Threat Detection Agent

A multi-vector cybersecurity analysis platform that detects and categorizes threat signatures across SQL Injection, Reconnaissance URLs, Steganography, and DDoS traffic logs. Built with Python, Streamlit, SQLite, and automated PDF report generation.

---

## 🚀 Features

- **SQL Injection (SQLi) Detection:** Analyzes input strings using pattern matching and signature verification.
- **Reconnaissance URL Inspector:** Validates domains, detects phishing/scan indicators, and integrates live threat intelligence via VirusTotal.
- **Steganography Analyzer:** Inspects image entropy, spatial pixel correlation, and histogram variance to identify hidden payload signatures.
- **DDoS Traffic Monitor:** Identifies volume-based traffic spikes and cross-references source IPs using hybrid heuristics and AbuseIPDB live lookups.
- **Role-Based Authentication:** Multi-user support with custom authentication (`user` vs `admin`) and SQLite backend log history.
- **Automated AI & PDF Summaries:** Generates security report PDFs using ReportLab.

---

## 📁 Project Structure

```text
my_cybersecurity_project/
│
├── datasets/                 # Threat signature & traffic datasets
│   ├── sqld.csv              # SQL Injection signatures
│   ├── recond.csv            # Reconnaissance domain/URL patterns
│   ├── ddos.csv              # DDoS traffic signatures
│   └── dataset_final.csv    # Wireshark traffic packet datasets
│
├── reports/                  # Generated PDF incident reports
├── ai.py                     # ReportLab PDF report generation engine
├── db.py                     # SQLite database initialization & auth logic
├── server.py                 # Flask API endpoint
├── tools.py                  # Core threat detection engines (SQLi, Recon, Stego, DDoS)
├── ui.py                     # Interactive Streamlit dashboard UI
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
=======
# cybersecurity_initialproject
Cybersecurity AI Threat Detection Engine – Multi-vector analysis for SQLi, Recon URLs, Steganography, and DDoS traffic using Python, Streamlit, SQLite, and automated PDF reporting.
>>>>>>> 81aab6ee27b302533f74affdd9b26c097ac542fb

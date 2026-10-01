# 🔐 Port Scanner Report Generator

A beginner-friendly network security application built using Python, Flask and Nmap.

The application scans an IP address or domain, detects open ports and services, performs basic risk classification, checks for possible CVE matches, stores scan history and generates HTML/PDF security reports.

---

## 🎯 Project Objective

The main objective of this project is to automate basic network security scanning and generate an easy-to-understand security report.

The application can:

- Accept IP addresses or domain names
- Perform Nmap scans automatically
- Detect open ports
- Identify services and products
- Detect service versions
- Classify ports based on basic security risk
- Generate security recommendations
- Perform CVE lookup using the NVD API
- Store scan results in SQLite
- Maintain scan history
- Display a security dashboard
- Generate HTML security reports
- Generate downloadable PDF reports

---

## 🛠️ Technologies Used

- **Python**
- **Flask**
- **Nmap**
- **python-nmap**
- **SQLite**
- **HTML**
- **CSS**
- **ReportLab**
- **NVD API**
- **Requests**

---

## 📁 Project Structure

```text
portscanner/
│
├── database/
│   ├── database.py
│   └── scans.db
│
├── exports/
│   └── security_report.pdf
│
├── reports/
│
├── scanner/
│   ├── cve_lookup.py
│   ├── nmap_scanner.py
│   ├── pdf_report.py
│   ├── recommendations.py
│   ├── risk.py
│   └── validator.py
│
├── static/
│   └── style.css
│
├── templates/
│   ├── dashboard.html
│   ├── history.html
│   ├── index.html
│   └── report.html
│
├── app.py
├── requirements.txt
├── README.md
└── test_scanner.py
# Ultimate Web Security Scanner v9.0

A modular, lightweight automated web vulnerability scanner and reconnaissance tool written in Python. Designed for educational purposes, security auditing, and assessing web application defenses.

---

## 🚀 Key Features

* **Smart Web Crawler:** Automatically discovers internal links, parameters, and HTML forms on the target web application.
* **Sensitive File & Path Enumeration:** Scans for common configuration files, backups, and exposed directories (e.g., `.env`, `robots.txt`, `.git/HEAD`, `wp-login.php`).
* **Security Headers & Configuration Audit:** Analyzes critical HTTP headers and settings:
  * SSL/TLS enforcement check
  * Clickjacking protection (`X-Frame-Options`, `Content-Security-Policy`)
  * CORS misconfigurations (`Access-Control-Allow-Origin: *`)
  * HTTP Strict Transport Security (HSTS)
  * Cookie security flags (`Secure`, `HttpOnly`)
* **Vulnerability Assessment Modules:** Tests parameters and inputs for common web vectors:
  * **SQL Injection (SQLi):** Error-based detection for MySQL, PostgreSQL, SQLite, and MSSQL.
  * **Cross-Site Scripting (XSS):** Reflected payload injection testing.
  * **Local File Inclusion (LFI):** Path traversal checks against system files (e.g., `/etc/passwd`).
  * **Command Injection (RCE):** Evaluates vulnerable parameter handling.
  * **Open Redirect & SSRF:** Checks handling of external URLs and redirect destinations.
  * **CSRF Analysis:** Detects POST forms lacking anti-CSRF tokens.
* **Automated Reporting:** Compiles all findings, severity levels, and logs into a structured text report (`scan_report.txt`).

---

## 📋 Requirements

* Python 3.x
* `requests`
* `beautifulsoup4`

You can install the required dependencies using:
```bash
pip install requests beautifulsoup4
---
⚠️ Disclaimer
This tool is created strictly for educational purposes and authorized security testing. Do not use it against targets without explicit prior legal permission.

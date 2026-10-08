# PhishGuard 🛡️
## Phishing URL Detector — Cybersecurity Portfolio Project

> **⚠️ Educational Project:** This tool analyses URL structure using heuristic rules. A SAFE result does not guarantee a website is harmless. Do not use this as your only security measure.

---

## 📋 Project Overview

**PhishGuard** is a web-based phishing URL detector built with Python and Flask. It analyses the structural properties of any submitted URL using 13 independent heuristic checks, computes a transparent risk score from 0–100, and classifies the URL as **SAFE**, **SUSPICIOUS**, or **PHISHING**. Every flag raised is accompanied by a plain-English explanation so the user understands exactly why a URL was deemed risky. Scan results are persisted in a local SQLite database, giving users a searchable and filterable scan history.

This project was built by a **2nd-year Computer Science & Engineering student** as part of a cybersecurity portfolio. The emphasis throughout the codebase is on **transparency and education** — there are no black-box decisions. Every check is an isolated, readable Python function with a clear docstring, the scoring weights are documented, and the UI surfaces the full reasoning behind every classification. The goal is not only to detect phishing URLs but to teach users *how* phishing URLs are constructed and *why* certain patterns are dangerous.

---

## ✨ Features

- 🔍 **13 heuristic security checks** covering protocol, domain, path, and encoding patterns
- 📊 **Risk score 0–100** with fully transparent, additive scoring
- 🚦 **SAFE / SUSPICIOUS / PHISHING classification** based on well-defined score thresholds
- 💬 **Detailed explanations** for every flagged item — no black-box results
- 🗄️ **Scan history** with search and filter functionality, backed by SQLite
- 🌑 **Dark cybersecurity-themed responsive UI** — looks great on desktop and mobile
- 🔌 **No external API calls** — pure URL string analysis, works completely offline
- 🔒 **CSRF protection** on all forms and **security headers** on every response
- 🗃️ **SQLite database** — zero setup, zero configuration needed
- 📚 **Beginner-friendly, well-commented Python code** — ideal for learning and presentation

---

## 🛠️ Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask 3.x |
| Database | SQLite (built-in) |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Icons | Font Awesome 6.5 (CDN) |
| Fonts | Inter (Google Fonts CDN) |
| Python Deps | Flask only (one dependency!) |

---

## 📁 Project Structure

```
phishguard/
├── app.py                  # Flask app, routes, security config
├── requirements.txt        # Python dependencies (Flask only)
├── database.db             # SQLite database (auto-created)
├── README.md
│
├── utils/
│   ├── __init__.py         # Package exports
│   ├── url_analyzer.py     # All 13 heuristic checks
│   └── database.py         # SQLite CRUD operations
│
├── templates/
│   ├── base.html           # Shared layout, navbar, footer
│   ├── index.html          # Landing page, scanner, dashboard
│   ├── result.html         # Scan result with score gauge
│   ├── history.html        # Scan history with search
│   ├── about.html          # Educational content
│   └── error.html          # 400/404 error pages
│
└── static/
    ├── css/
    │   └── style.css       # Dark cybersecurity theme
    └── js/
        └── script.js       # Donut chart, loading states, etc.
```

---

## ⚡ Quick Start

### Prerequisites

- Python 3.10 or higher
- pip (comes with Python)
- VS Code (recommended)

### Installation

**Step 1: Navigate to the project folder**
```bash
cd phishguard
```

**Step 2: Create a virtual environment**
```bash
python -m venv venv
```

**Step 3: Activate the virtual environment**

Windows:
```bash
venv\Scripts\activate
```

macOS / Linux:
```bash
source venv/bin/activate
```

**Step 4: Install dependencies**
```bash
pip install -r requirements.txt
```

**Step 5: Run the application**
```bash
python app.py
```

**Step 6: Open in browser**
```
http://127.0.0.1:5000
```

### VS Code Tips

- Open the `phishguard/` folder in VS Code
- Open the integrated terminal: **Ctrl+\`** (backtick)
- Run all commands in the integrated terminal
- Install the **Python** extension for syntax highlighting and IntelliSense

---

## 🔍 How URL Analysis Works

PhishGuard follows a strict, stateless analysis pipeline. At **no point** does the application visit, fetch, download, or interact with the submitted URL in any way.

1. **User submits URL** via the form on the landing page
2. **Flask validates the CSRF token** — if missing or invalid, the request is rejected with HTTP 400
3. **`normalize_url()`** adds `https://` if no scheme is present, then validates the overall URL structure using Python's `urllib.parse`
4. **`analyze_url()`** passes the parsed URL to all 13 independent check functions in sequence
5. **Each check** returns a result dictionary containing a `triggered` boolean, a human-readable `description`, and a `points_added` integer
6. **Total risk score** = sum of all `points_added` values, capped at 100
7. **Classification** is assigned based on the score thresholds (see table below)
8. **Result is saved** to the SQLite database via a parameterised INSERT
9. **Result page is rendered** with the score, classification, donut chart, and full check breakdown

> [!NOTE]
> Because the app never makes outbound network requests, it is safe to scan any URL — including known malicious ones — without any risk of accidentally loading harmful content.

---

## 📊 Risk Scoring Methodology

### The 14 Heuristic Checks

| # | Check | Trigger Condition | Risk Points |
|---|---|---|---|
| 1 | HTTPS Protocol | URL uses HTTP not HTTPS | +15 |
| 2 | IP Address | Raw IP instead of domain | +25 |
| 3 | URL Shortener | Known shortening service | +15 |
| 4 | Suspicious Keywords | Generic phishing terms or brand spoofing | +15 each (max +30) |
| 5 | URL Length (very long) | More than 75 characters | +10 |
| 6 | URL Length (moderate) | 54–75 characters | +5 |
| 7 | Excessive Subdomains | More than 2 subdomains | +10 |
| 8 | @ Symbol | @ in URL authority | +10 |
| 9 | Double-Slash Redirect | // in URL path | +5 |
| 10 | Suspicious TLD | .tk, .ml, .xyz etc. | +10 |
| 11 | Excessive Hyphens | More than 2 hyphens in domain | +5 |
| 12 | Excessive Dots | More than 4 dots in URL | +5 |
| 13 | Punycode/IDN | xn-- encoding in domain | +15 |
| 14 | Non-Standard Port | Port other than 80 or 443 | +5 |
| 15 | Special Characters | Obfuscation symbols (~, ;, {, }, hex %) | +10 |

### Classification Thresholds

| Score Range | Classification | Meaning |
|---|---|---|
| 0–30 | 🟢 SAFE | No significant risk indicators |
| 31–60 | 🟡 SUSPICIOUS | Some risk indicators present |
| 61–100 | 🔴 PHISHING | Multiple strong risk indicators |

---

## 🧪 Test Examples

Use these URLs during your college presentation to demonstrate a range of outcomes. Results are illustrative — exact scores depend on the URL as entered.

| # | URL | Expected Classification | Why |
|---|---|---|---|
| 1 | `https://www.google.com` | SAFE | Clean HTTPS, well-known domain |
| 2 | `https://example.com` | SAFE | Clean HTTPS, simple domain |
| 3 | `http://example.com` | SUSPICIOUS | No HTTPS (+15) |
| 4 | `http://192.168.1.1/login` | PHISHING | IP + HTTP + keyword: +15+25+10 = 50 |
| 5 | `https://bit.ly/3xyz` | SUSPICIOUS | URL shortener +15 |
| 6 | `https://paypal.com.secure-login.verify.tk` | PHISHING | Many flags triggered |
| 7 | `https://secure-login-verify-paypal.com` | SUSPICIOUS/PHISHING | Keywords + hyphens |
| 8 | `https://xn--pypl-4qa.com` | PHISHING | Punycode domain +15, likely more |
| 9 | `http://www.amazon.com.account-update.xyz/signin` | PHISHING | Multiple flags |
| 10 | `https://microsoft.com` | SAFE | Clean URL |

> **Note:** These are illustrative examples for demonstration purposes. Real-world results depend on the exact URL string submitted.

---

## 🔒 Security Features

PhishGuard is built with several security controls appropriate for a student web project:

- **CSRF Protection** — Every POST form includes a session-bound HMAC-verified token generated server-side. Requests with missing or mismatched tokens are rejected immediately with HTTP 400.
- **Input Validation** — All submitted URLs are validated for structure and length before any analysis is performed. Invalid inputs are rejected with descriptive error messages.
- **No URL Fetching** — The application never visits, downloads, or interacts with submitted URLs. Analysis is entirely based on the URL string itself.
- **Parameterised SQL** — Every database query uses `?` placeholders to prevent SQL injection. String formatting is never used to construct queries.
- **Security Headers** — Every HTTP response includes `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`.
- **Content Length Limit** — Incoming request bodies are capped at **8 KB** to prevent excessively large input from being processed.

---

## ⚠️ Limitations

Understanding what PhishGuard *cannot* do is just as important as knowing what it can:

- Cannot detect sophisticated phishing sites hosted on **legitimate HTTPS domains** (e.g. `https://google.com.evil-site.com` would score differently to `https://evil-login.google.com`)
- No **real-time threat intelligence** or blocklist lookup — known bad domains are not checked
- Does not analyse **page content**, **SSL certificate validity**, or **WHOIS / domain age** data
- May produce **false positives** (flagging safe URLs with unusual structure) or **false negatives** (missing clever phishing URLs)
- Designed for **education** — not suitable as a standalone production security tool
- Analysis results may change as new checks are added in future versions

---

## 🚀 Future Improvements

These enhancements are planned or recommended for future development:

1. **Machine Learning Classification** — Train a supervised model on publicly available labeled phishing datasets (e.g. PhishTank, UCI Phishing Dataset) for probabilistic, adaptive detection
2. **VirusTotal API Integration** — Cross-reference submitted URLs against VirusTotal's aggregated threat intelligence from 70+ antivirus engines
3. **Google Safe Browsing API** — Use Google's actively maintained phishing and malware database for real-time lookup
4. **WHOIS / Domain Age** — Flag domains registered fewer than 30 days ago, a common indicator of throwaway phishing infrastructure
5. **DNS Analysis** — Inspect DNS records for suspicious configurations such as wildcard records, very low TTL, or newly delegated nameservers
6. **SSL Certificate Inspector** — Verify certificate validity, expiry, and issuer trustworthiness to complement the protocol check
7. **Browser Extension** — Integrate the analysis engine into a browser extension that scans URLs before navigation
8. **Email Phishing Detection** — Parse and analyse email headers, body links, and sender domains for phishing indicators
9. **QR Code Phishing** — Decode QR code images and pass the embedded URL through the analysis pipeline
10. **Real-time Threat Feeds** — Subscribe to open threat intelligence (OTI) feeds such as MISP or OpenPhish for continuously updated indicators

---

## 🐛 Common Errors & Fixes

| Error | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: flask` | Flask not installed in the active environment | Run `pip install -r requirements.txt` |
| `venv\Scripts\activate` fails | PowerShell execution policy blocks scripts | Run: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| Port 5000 already in use | Another process is already using port 5000 | Change port: `app.run(port=5001)` in `app.py` |
| Template not found | Running `python app.py` from the wrong directory | Run `python app.py` from inside the `phishguard/` folder |
| Database locked | Multiple app instances running simultaneously | Stop all Python processes and restart with a single instance |
| CSRF token invalid | Browser tab has been open too long or session expired | Refresh the page and resubmit the form |

---

## 📖 Code Structure Explained

A brief guide to each key file to help you navigate and present the codebase:

- **`app.py`** — Flask routes, CSRF token generation and validation, security headers configuration, and application startup. Think of it as the **controller** layer — it coordinates input, processing, and output but contains no business logic itself.

- **`utils/url_analyzer.py`** — Pure Python functions with no Flask dependency. Each of the 13 heuristic checks is an **isolated, individually testable function**. You can import and call any check function from a plain Python script or unit test without starting Flask.

- **`utils/database.py`** — All database code lives in one place. Uses Python context managers (`with` statements) to guarantee connections are always closed, even if an exception occurs. No raw SQL strings with user data — all queries use `?` placeholders.

- **`templates/base.html`** — Jinja2 parent template that all pages extend using `{% extends %}`. The navbar, footer, CSRF meta tag, and CSS/JS imports are defined here once and inherited everywhere.

- **`static/css/style.css`** — Built around CSS custom properties (variables). The entire colour scheme, spacing, and typography system is controlled via `:root` variables at the top of the file. Change `--accent` to completely rebrand the visual theme.

- **`static/js/script.js`** — Progressive enhancement: the app is **fully functional without JavaScript**. JS adds the animated donut chart on the result page, client-side loading state animations, and smooth UI transitions. If JS is disabled, all core functionality still works.

---

## 🎓 For College Presentation

Suggested walkthrough to make the most of your demo:

1. **Open the landing page** — let the dark cybersecurity theme make a first impression
2. **Scan test URL #4** (`http://192.168.1.1/login`) — it triggers IP address, HTTP, and keyword flags simultaneously and should score high
3. **Walk through the result page** — point to the donut chart, score value, classification badge, and the per-flag explanations
4. **Navigate to History** — demonstrate that scans persist across sessions and can be searched
5. **Open `url_analyzer.py` in VS Code** — walk through one check function line-by-line to show the code is readable and educational
6. **Show the CSRF token** — open Browser DevTools → Application → Cookies and point to the `csrf_token` cookie
7. **Use the About page** — explain phishing concepts to contextualise the project for non-technical audience members
8. **Mention future improvements** — bringing up ML integration, VirusTotal, and the browser extension shows depth of knowledge and forward thinking

---

## 📄 Ethical Disclaimer

This project is intended **solely for educational and defensive cybersecurity purposes.**

- ❌ Do **not** use this tool to assist in planning, conducting, or supporting phishing attacks or any other illegal activity.
- ⚠️ A **SAFE** classification does **not** mean a URL is safe. Always verify through multiple means before trusting a URL.
- 🔒 This project does **not** collect any personal data from users.
- 💾 Submitted URLs are stored **locally** in your own SQLite database file on your own machine — they are never sent to any server.
- 🚫 No submitted URL is **ever visited, downloaded, or interacted with** by this tool.

Built with ❤️ for learning cybersecurity.

---

## 📜 License

**MIT License** — free to use, modify, and distribute for educational purposes.

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

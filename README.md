# Web Threat Intelligence System

Full-stack cybersecurity platform: phishing URL, email and SMS spam detection
using a hybrid ML (TF-IDF + Logistic Regression / Naive Bayes) + heuristic
rules engine. Built with Flask, Bootstrap 5, Chart.js, SQLite and scikit-learn.

## Features
- Authentication (register / login / logout / forgot password with security question)
- Strong password validation (upper + lower + digit + symbol, 8+ chars) and hashing (Werkzeug)
- Dashboard with totals, safe vs risky stats, recent activity and Chart.js graphs
- 3-in-1 multi-threat detection: URL / Email / SMS
- Hybrid AI: TF-IDF char/word n-grams + Logistic Regression + Naive Bayes + 12+ heuristics
  (HTTPS, URL length, '@', dots, shorteners, IP-URLs, punycode, suspicious keywords,
  spam phrases, OTP traps, capitalization, embedded link analysis, etc.)
- Risk score %, Safe / Medium / High Risk verdict, reasons and security suggestions
- History: search, filter, delete, **PDF export** (ReportLab)
- Cybersecurity AI chatbot (rule-based, no external API)
- Recovery Center checklist for users who already clicked a malicious link
- Admin panel: users, scans, risky activity monitor, activity logs
- Dark theme, responsive Bootstrap 5 UI, toast notifications, loading states
- Activity logs and session security (HTTP-only, SameSite cookies)

## Run locally
```bash
cd web_threat_intel
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open http://localhost:5000

The first registered user automatically becomes admin.
ML models are trained automatically on first boot (synthetic seed dataset).
To retrain on real data, edit `model/train_models.py` and run:
```bash
python model/train_models.py
```

## Project structure
```
web_threat_intel/
├── app.py                 # Flask routes + bootstrap
├── config.py              # Config (secret key, DB URI, session security)
├── models.py              # SQLAlchemy: User, Scan, ActivityLog
├── forms.py               # WTForms with strong validation
├── requirements.txt
├── model/
│   └── train_models.py    # TF-IDF + LR + NB training (URL & text)
├── utils/
│   ├── detector.py        # Hybrid ML + heuristic detector
│   ├── chatbot.py         # Cybersecurity chatbot
│   └── pdf.py             # ReportLab PDF report builder
├── templates/             # Jinja2 templates (Bootstrap 5, dark theme)
└── static/css|js          # Custom styles + JS
```

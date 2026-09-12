---
title: ZeroTrust AI Vulnerability Assessment
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# ZeroTrust AI Vulnerability Assessment Platform

A Flask web app with account registration + email verification, and a
lightweight automated security scanner: it checks a target site's HTTP
security headers, TLS certificate health, and HTTPS enforcement, then
returns a 0–100 risk score with plain-English findings.

## Features

- Registration with hashed passwords, email verification (token expires
  in 24h), and login/logout (Flask-Login)
- Rate limiting on login and scan endpoints (Flask-Limiter)
- CSRF protection on all forms (Flask-WTF)
- Vulnerability scanner (`scanner.py`) checking:
  - Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
  - Server/X-Powered-By information disclosure
  - HTTP → HTTPS redirect enforcement
  - TLS certificate validity and expiry
- SSRF protections: scans refuse private/loopback/link-local/cloud-metadata
  targets
- Scan history per user, stored in SQLite (or any `DATABASE_URL` you set)

## Project structure

```
app.py            # app factory, routes for home + error pages
config.py         # config from environment variables
extensions.py     # db, csrf, limiter, mail, login_manager
models.py         # User, Scan
forms.py          # WTForms
auth.py           # register / login / logout / email verification
scan_routes.py    # dashboard / new scan / history / detail
scanner.py        # the actual scanning logic
templates/        # Jinja templates
static/css/       # styling
Dockerfile        # for Hugging Face Spaces (Docker SDK)
```

## Local setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # then edit .env with your own values
python app.py
```

App runs at `http://localhost:7860`.

If `MAIL_USERNAME` is not set, verification emails aren't actually sent —
the verification link is printed to the console/log instead, so you can
still test the flow locally without SMTP credentials.

### Gmail app password

`MAIL_PASSWORD` must be a 16-character **App Password**, not your normal
Gmail password (requires 2-Step Verification enabled on the Google
account): Google Account → Security → 2-Step Verification → App passwords.

## Deploying to Hugging Face Spaces

1. Create a new Space at https://huggingface.co/new-space, choose **Docker**
   as the Space SDK (this README's frontmatter already sets that if you
   push it as-is).
2. Push this project's files to the Space's git repo (or upload them via
   the web UI) — including the `Dockerfile`.
3. In the Space's **Settings → Repository secrets**, add:
   - `SECRET_KEY` — a long random string
   - `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER` — if you want
     real verification emails sent
   - `DATABASE_URL` — optional; omit to use SQLite inside the container
4. The Space will build the Docker image and serve the app on port 7860
   automatically.

### Important: SQLite is not persistent on free Spaces

The default SQLite database lives inside the container's filesystem. On
the free CPU tier, Spaces can restart/rebuild the container, which wipes
that file — registered users and scan history would be lost. For a real
deployment:

- Enable a Space's **persistent storage** add-on and point `DATABASE_URL`
  at a file under `/data`, **or**
- Point `DATABASE_URL` at an external database (e.g. a free Postgres
  instance from Supabase/Neon/Railway).

## Limitations / next steps

- The scanner is rule-based (headers/TLS/redirect checks), not a full
  penetration test — good for a course project, not a compliance audit.
- No password-reset flow yet (only registration/email-verification/login).
- No admin role/dashboard for the `role` field on `User` yet.
- PDF report export (e.g. via ReportLab) could be added to `scan_routes.py`
  for a downloadable report per scan.

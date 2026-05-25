# 🛡️ CENTURION Tactical Ledger

A full-stack peer-to-peer money transfer application built with FastAPI and PostgreSQL. Designed with production financial software patterns including atomic transactions, duplicate-request protection, and a complete audit trail.

---

## What It Does

Users can create a vault account, send money to other users by email or Vault ID, and view their full transaction history. The system handles concurrent transfers safely and prevents common failure modes like double charges from network retries.

---

## Core Features

- **Secure Account System** — JWT sessions stored in httpOnly cookies, bcrypt password hashing, and a separate 6-digit transaction PIN for transfer authorization
- **PIN Lockout** — Account locks for 30 minutes after 5 consecutive failed PIN attempts
- **Safe Money Transfers** — Row-level database locking prevents two simultaneous transfers from overdrawing the same account
- **Duplicate Request Protection** — Idempotency keys ensure that a retried network request returns the original transaction instead of executing a second charge
- **Multi-Currency Support** — Transfers in NGN, USD, EUR, and GBP with internal NGN base conversion
- **Transaction History** — Paginated ledger showing all sends and receives with counterparty details
- **PDF Ledger Export** — Download a formatted PDF statement of all transactions
- **Spending Analytics** — Rule-based analysis of transaction history showing net flow, spending trends (increasing/stable/decreasing), most active currency, and a projected monthly outflow
- **Email Notifications** — Sender and receiver both get email alerts on every completed transfer
- **Immutable Audit Log** — Every financial action is recorded with the user's IP address, user agent, and full details for compliance purposes

---

## Security Design Decisions

| Decision | Reason |
|---|---|
| PIN sent in `X-Pin` request header, not URL | URLs are written to server access logs; headers are not |
| `Decimal` type for all money values | Floating-point arithmetic produces rounding errors on currency calculations |
| `SELECT ... FOR UPDATE` row locking on transfers | Prevents race conditions where concurrent requests read the same balance before either has written |
| Idempotency key checked before processing | Ensures network retries do not create duplicate transactions |
| Passwords and PINs filtered from logs | A custom logging filter strips sensitive values before they are written |
| Security headers on every response | `X-Frame-Options`, `X-XSS-Protection`, `Content-Security-Policy`, and `HSTS` added via middleware |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI (Python) |
| Database | PostgreSQL via SQLAlchemy 2.0 ORM |
| Authentication | JWT (python-jose) + bcrypt (passlib) |
| Email | fastapi-mail (SMTP) |
| Frontend | Vanilla JavaScript, Tailwind CSS, Chart.js |
| PDF Generation | ReportLab |
| Rate Limiting | slowapi |

---

## Database Schema

Three tables:

- **accounts** — stores credentials, hashed PIN, balance, lockout state
- **transactions** — records every transfer with sender, receiver, amount, currency, idempotency key, and a unique signature
- **audit_logs** — append-only compliance log with JSONB details, IP address, and user agent

---

## Local Setup

**Prerequisites:** Python 3.11+, PostgreSQL

```bash
# 1. Clone the repository
git clone https://github.com/Tempest00-max/centurion_ledger.git
cd centurion_ledger/temp_app

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create a .env file
# DATABASE_URL=postgresql://user:password@localhost:5432/centurion
# SECRET_KEY=your-secret-key-here
# MAIL_USERNAME=your@email.com
# MAIL_PASSWORD=your-email-password
# MAIL_FROM=your@email.com
# MAIL_SERVER=smtp.gmail.com
# MAIL_PORT=587

# 4. Initialize the database
psql -U postgres -d centurion -f schema.sql

# 5. Run the application
uvicorn app.main:app --reload
```

Open `http://localhost:8000` in your browser.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/signup` | Create a new account |
| `POST` | `/token` | Login and receive JWT |
| `POST` | `/logout` | Clear auth cookie |
| `GET` | `/accounts/me` | Get current user profile |
| `PATCH` | `/accounts/update` | Update name, email, PIN, or password |
| `GET` | `/lookup?target=` | Look up a recipient by email or Vault ID |
| `POST` | `/transfer/` | Execute a transfer |
| `GET` | `/transactions/` | Get paginated transaction history |
| `GET` | `/transactions/export` | Export transactions as PDF or JSON |
| `GET` | `/forecast/` | Get spending analytics and projections |
| `GET` | `/health` | Health check |

---

## Project Structure

```
temp_app/
├── app/
│   ├── main.py        # API routes, middleware, business logic
│   ├── models.py      # SQLAlchemy database models
│   ├── schemas.py     # Pydantic request/response validation
│   ├── auth.py        # Password hashing, PIN hashing, JWT handling
│   └── database.py    # Database session configuration
├── static/
│   └── index.html     # Single-page frontend (Vanilla JS + Tailwind)
├── schema.sql         # Database table definitions
├── requirements.txt
└── .env               # Environment variables (not committed)
```

---

## Author

Built by [Tempest00-max](https://github.com/Tempest00-max)

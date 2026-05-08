# 🛡️ CENTURION Tactical Ledger
**High-Fidelity Fintech Dashboard & Secure Transaction Engine**

A production-grade financial system built for mission-critical balance tracking. It features atomic database integrity, AI-powered forecasting, and a hardened tactical UI.

## 🚀 Technical Highlights
* **Atomic Data Integrity:** Implements row-level locking (`with_for_update`) to prevent "double-spending" during concurrent transfers.
* **Hardened Security:** Uses Secret-Header PIN validation (`X-Pin`) to keep sensitive authorization out of server logs.
* **Fault-Tolerant Logic:** Utilizes Idempotency Keys to ensure network failures don't result in duplicate transactions.
* **AI Forecast Engine:** Analyzes historical patterns to generate monthly outflow projections and spending insights.

## 🛠️ Tech Stack
* **Backend:** FastAPI (Python), SQLAlchemy ORM, Pydantic.
* **Database:** PostgreSQL (Cloud-hosted via Neon.tech).
* **Frontend:** Vanilla JavaScript (ES6+), Tailwind CSS, Chart.js.
* **Notifications:** Background Task-based Email alerts via SMTP.

## ✨ Core Features
* 🔐 **Multi-Factor Auth:** JWT-based sessions combined with 6-digit Security PIN verification.
* 💱 **Global Routing:** Real-time multi-currency support (NGN, USD, EUR, GBP).
* 📊 **Tactical Visualization:** Interactive balance history with precision tooltips and data filtering.
* 🤖 **Financial Intelligence:** Automated spending trend analysis and AI risk recommendations.
* 📄 **Audit Compliance:** Instant PDF ledger export and immutable audit logging.

## 📦 Local Installation
1.  **Clone the Repo:** `git clone https://github.com/Tempest00-max/centurion_ledger.git`
2.  **Environment Setup:** Create a `.env` file with your `DATABASE_URL` and `SECRET_KEY`.
3.  **Install Dependencies:** `pip install -r requirements.txt`
4.  **Run Application:** `uvicorn app.main:app --reload`
# Email Registration & OTP Verification System

A minimal, secure, and production-ready email registration and one-time password (OTP) verification service built with **FastAPI**, **SQLAlchemy**, **Argon2id**, **Pydantic Settings**, and a lightweight frontend.

---

## Features & Flow

1. **Register (`POST /api/auth/register`)**:
   - Submits email and password.
   - User is created with `is_verified = False`.
   - Password is securely hashed using **Argon2id**.
   - Generates a cryptographically random 6-digit numeric OTP, stores an Argon2id hash of it with an expiry (10 min), and dispatches it via email.

2. **Verify (`POST /api/auth/verify-otp`)**:
   - Submits email and 6-digit OTP.
   - Checks that the code matches the stored hash, has not expired, and has not exceeded maximum attempts (5 attempts).
   - Each incorrect attempt increments the attempt counter.
   - Upon successful match, marks `user.is_verified = True` and deletes the OTP record to prevent replay attacks.

3. **Resend (`POST /api/auth/resend-otp`)**:
   - Allowed, but rate-limited via a cooldown window (60 seconds).
   - Generating a new OTP automatically invalidates and removes any previous OTP for the user.

4. **Minimal Frontend (`GET /`)**:
   - A clean, responsive single-page interface served at the root URL.
   - Guides the user through Registration &rarr; OTP Verification &rarr; Verified Success screen.
   - Includes real-time cooldown countdown on the Resend button and error alerts.

---

## Data Models

### `users` Table
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | Integer | Primary Key | Unique user identifier |
| `email` | String(255) | Unique, Indexed, Not Null | Normalized user email |
| `password_hash` | String(255) | Not Null | Argon2id password hash |
| `is_verified` | Boolean | Default False, Not Null | Email verification status |
| `created_at` | DateTime (UTC) | Not Null | User registration timestamp |

### `email_otps` Table
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | Integer | Primary Key | Unique OTP record identifier |
| `user_id` | Integer | Foreign Key (`users.id`), Indexed | Referenced user ID |
| `email` | String(255) | Indexed, Not Null | Associated email |
| `otp_hash` | String(255) | Not Null | Argon2id hash of the 6-digit OTP |
| `expires_at` | DateTime (UTC) | Not Null | OTP expiration timestamp |
| `attempts` | Integer | Default 0, Not Null | Failed verification attempts |
| `created_at` | DateTime (UTC) | Not Null | OTP issue timestamp (used for cooldown) |

---

## Security Architecture

- **No Plaintext Passwords or OTPs**: Both user passwords and 6-digit OTP codes are hashed with **Argon2id** (`argon2-cffi`). Even in the event of an unauthorized database leak, OTPs cannot be recovered or brute-forced offline.
- **Brute-Force Protection**: OTP records track verification attempts (`attempts`). If invalid OTP submissions exceed `OTP_MAX_ATTEMPTS` (default: 5), the OTP record is purged, preventing brute-force searches across the 1,000,000 numeric code space.
- **Expiration Window**: Strict UTC timestamp checks ensure OTPs cannot be used after `OTP_EXPIRE_MINUTES` (default: 10 minutes).
- **Rate-Limiting / Cooldown**: `OTP_RESEND_COOLDOWN_SECONDS` (default: 60s) blocks spamming and mail-bombing.
- **Strict Invalidation**: Requesting a new OTP immediately purges existing OTP records for that account.
- **Immediate Cleanup**: Once verified, the OTP record is deleted immediately from the database.

---

## Directory Structure

```
.
├── app/
│   ├── main.py            # App creation, router registration, minimal frontend
│   ├── config.py          # Settings from .env (pydantic-settings)
│   ├── database.py        # Engine, SessionLocal, get_db
│   ├── models.py          # User, EmailOTP models
│   ├── schemas.py         # Pydantic request/response models
│   ├── security.py        # Argon2id password hashing, OTP generation/hashing
│   ├── email.py           # SMTP sending & dev console simulator
│   ├── services/
│   │   └── otp.py         # issue_otp, verify_otp core business logic
│   └── routers/
│       └── auth.py        # /register, /verify-otp, /resend-otp endpoints
├── tests/
│   └── test_otp.py        # Pytest test suite (13 comprehensive tests)
├── .env.example           # Example configuration template
├── .gitignore             # Comprehensive Git ignore rules
├── requirements.txt       # Project dependencies
└── README.md              # Project documentation
```

---

## Getting Started

### 1. Requirements & Installation

Clone the repository and install dependencies:
```bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name

# Create and activate virtual environment (optional but recommended)
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Environment Configuration

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

#### Local Development / Testing Mode
Leave `SMTP_HOST=""`. In this mode, generated OTPs are printed directly to the terminal console without connecting to an external mail provider:
```env
SMTP_HOST=""
```

#### Production / Live Email Delivery (e.g. Resend / SendGrid / Brevo)
Provide your SMTP credentials:
```env
SMTP_HOST="smtp.resend.com"
SMTP_PORT=587
SMTP_USER="resend"
SMTP_PASSWORD="re_xxxxxxxxxxxx"
SMTP_FROM_EMAIL="onboarding@resend.dev"
SMTP_FROM_NAME="Auth Service"
SMTP_USE_TLS=true
```

### 3. Run the Server

Start the application with Uvicorn:
```bash
uvicorn app.main:app --reload
```

The application will be accessible at:
- **Frontend UI**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Documentation**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## API Endpoints

### 1. Register User
`POST /api/auth/register`
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```
**Response (`201 Created`):**
```json
{
  "message": "Registration successful. A verification code has been sent to your email."
}
```

### 2. Verify OTP
`POST /api/auth/verify-otp`
```json
{
  "email": "user@example.com",
  "otp": "482910"
}
```
**Response (`200 OK`):**
```json
{
  "message": "Email successfully verified."
}
```

### 3. Resend OTP
`POST /api/auth/resend-otp`
```json
{
  "email": "user@example.com"
}
```
**Response (`200 OK`):**
```json
{
  "message": "A new verification OTP has been sent to your email."
}
```
*(Returns `429 Too Many Requests` if requested before the 60-second cooldown expires).*

---

## Running the Test Suite

Run all tests with Pytest:
```bash
pytest tests/test_otp.py -v
```

All 13 test cases run in an isolated in-memory SQLite database verifying password hashing, OTP generation/hashing, email simulation, verification logic, attempt counters, expiration, cooldowns, and all router endpoints.

---

## License

MIT

# Email Registration & OTP Verification

A minimal, secure FastAPI service for email registration and OTP verification using Argon2id password and OTP hashing, rate-limiting, and an embedded frontend.

## Quickstart

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env

# 3. Run the application
uvicorn app.main:app --reload
```

- **Frontend UI**: http://127.0.0.1:8000
- **API Docs**: http://127.0.0.1:8000/docs

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Minimal verification UI |
| `POST` | `/api/auth/register` | Register user (`is_verified = false`) & dispatch OTP |
| `POST` | `/api/auth/verify-otp` | Verify 6-digit OTP & mark user verified |
| `POST` | `/api/auth/resend-otp` | Rate-limited (60s) resend (invalidates old OTP) |

## Configuration (`.env`)

- `SMTP_HOST`: Leave blank to simulate emails in the terminal console, or set to your provider (e.g. `smtp.resend.com`).
- `OTP_EXPIRE_MINUTES`: Expiry window in minutes (default: `10`).
- `OTP_RESEND_COOLDOWN_SECONDS`: Cooldown before allowing resend (default: `60`).
- `OTP_MAX_ATTEMPTS`: Max failed attempts before invalidating OTP (default: `5`).

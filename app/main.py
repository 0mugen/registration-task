from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from app.config import get_settings
from app.database import Base, engine
from app.routers import auth

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure database tables exist
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    lifespan=lifespan,
)

# Register routers
app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def serve_frontend():
    """Minimal, secure, standalone frontend for registration and OTP verification."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Registration & OTP Verification</title>
  <style>
    :root {
      --primary: #2563eb;
      --primary-hover: #1d4ed8;
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --text: #0f172a;
      --text-muted: #64748b;
      --border: #e2e8f0;
      --danger: #ef4444;
      --success: #10b981;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 1rem;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -2px rgba(0, 0, 0, 0.05);
      width: 100%;
      max-width: 420px;
      padding: 2rem;
    }
    h1 {
      font-size: 1.35rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      text-align: center;
    }
    p.subtitle {
      color: var(--text-muted);
      font-size: 0.9rem;
      text-align: center;
      margin-bottom: 1.5rem;
    }
    .form-group {
      margin-bottom: 1.2rem;
    }
    label {
      display: block;
      font-size: 0.85rem;
      font-weight: 600;
      margin-bottom: 0.4rem;
    }
    input {
      width: 100%;
      padding: 0.65rem 0.85rem;
      font-size: 0.95rem;
      border: 1px solid var(--border);
      border-radius: 6px;
      outline: none;
      transition: border-color 0.15s;
    }
    input:focus {
      border-color: var(--primary);
    }
    .otp-input {
      font-size: 1.5rem;
      text-align: center;
      letter-spacing: 0.5rem;
      font-weight: 700;
      font-family: monospace;
    }
    button {
      width: 100%;
      padding: 0.75rem;
      font-size: 0.95rem;
      font-weight: 600;
      color: #fff;
      background-color: var(--primary);
      border: none;
      border-radius: 6px;
      cursor: pointer;
      transition: background-color 0.15s;
    }
    button:hover:not(:disabled) {
      background-color: var(--primary-hover);
    }
    button:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }
    .btn-secondary {
      background-color: transparent;
      color: var(--primary);
      border: 1px solid var(--border);
      margin-top: 0.6rem;
    }
    .btn-secondary:hover:not(:disabled) {
      background-color: #f1f5f9;
    }
    .alert {
      padding: 0.75rem;
      border-radius: 6px;
      font-size: 0.875rem;
      margin-bottom: 1rem;
      display: none;
    }
    .alert-error {
      background-color: #fef2f2;
      color: var(--danger);
      border: 1px solid #fecaca;
    }
    .alert-success {
      background-color: #ecfdf5;
      color: var(--success);
      border: 1px solid #a7f3d0;
    }
    .hidden { display: none !important; }
    .footer-note {
      text-align: center;
      font-size: 0.8rem;
      color: var(--text-muted);
      margin-top: 1.25rem;
    }
    .pill {
      display: inline-block;
      background: #eff6ff;
      color: var(--primary);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-weight: 600;
      word-break: break-all;
    }
  </style>
</head>
<body>
  <div class="card">
    <div id="alertBox" class="alert"></div>

    <!-- Step 1: Register -->
    <div id="stepRegister">
      <h1>Create Account</h1>
      <p class="subtitle">Enter your email and password to begin</p>
      <form id="formRegister">
        <div class="form-group">
          <label for="regEmail">Email Address</label>
          <input type="email" id="regEmail" required placeholder="you@example.com" autocomplete="email">
        </div>
        <div class="form-group">
          <label for="regPassword">Password</label>
          <input type="password" id="regPassword" required minlength="8" placeholder="At least 8 characters" autocomplete="new-password">
        </div>
        <button type="submit" id="btnRegister">Register &amp; Send OTP</button>
      </form>
    </div>

    <!-- Step 2: Verify OTP -->
    <div id="stepVerify" class="hidden">
      <h1>Verify Email</h1>
      <p class="subtitle">Enter the 6-digit code sent to <br><span id="targetEmail" class="pill"></span></p>
      <form id="formVerify">
        <div class="form-group">
          <label for="otpCode">6-Digit Code</label>
          <input type="text" id="otpCode" class="otp-input" maxlength="6" pattern="\\d{6}" required placeholder="------" autocomplete="one-time-code">
        </div>
        <button type="submit" id="btnVerify">Verify OTP</button>
      </form>
      <button type="button" id="btnResend" class="btn-secondary">Resend OTP</button>
      <button type="button" id="btnBack" class="btn-secondary" style="border:none; color:var(--text-muted);">Back to Registration</button>
    </div>

    <!-- Step 3: Success -->
    <div id="stepSuccess" class="hidden" style="text-align: center;">
      <div style="font-size: 3rem; color: var(--success); margin-bottom: 0.5rem;">✓</div>
      <h1>Email Verified!</h1>
      <p class="subtitle">Your account has been successfully verified.</p>
      <button type="button" id="btnReset">Register Another User</button>
    </div>

    <div class="footer-note">Minimal &amp; Secure OTP Authentication</div>
  </div>

  <script>
    const alertBox = document.getElementById('alertBox');
    const stepRegister = document.getElementById('stepRegister');
    const stepVerify = document.getElementById('stepVerify');
    const stepSuccess = document.getElementById('stepSuccess');
    const targetEmail = document.getElementById('targetEmail');

    const formRegister = document.getElementById('formRegister');
    const formVerify = document.getElementById('formVerify');
    const btnRegister = document.getElementById('btnRegister');
    const btnVerify = document.getElementById('btnVerify');
    const btnResend = document.getElementById('btnResend');
    const btnBack = document.getElementById('btnBack');
    const btnReset = document.getElementById('btnReset');

    let currentEmail = '';
    let cooldownTimer = null;

    function showAlert(msg, isSuccess = false) {
      alertBox.textContent = msg;
      alertBox.className = 'alert ' + (isSuccess ? 'alert-success' : 'alert-error');
      alertBox.style.display = 'block';
    }

    function clearAlert() {
      alertBox.style.display = 'none';
      alertBox.textContent = '';
    }

    function startCooldown(seconds = 60) {
      clearInterval(cooldownTimer);
      let remaining = seconds;
      btnResend.disabled = true;
      btnResend.textContent = `Resend OTP in ${remaining}s`;

      cooldownTimer = setInterval(() => {
        remaining -= 1;
        if (remaining <= 0) {
          clearInterval(cooldownTimer);
          btnResend.disabled = false;
          btnResend.textContent = 'Resend OTP';
        } else {
          btnResend.textContent = `Resend OTP in ${remaining}s`;
        }
      }, 1000);
    }

    formRegister.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearAlert();
      btnRegister.disabled = true;
      btnRegister.textContent = 'Sending OTP...';

      const email = document.getElementById('regEmail').value.trim();
      const password = document.getElementById('regPassword').value;

      try {
        const res = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || data.message || 'Registration failed');
        }

        currentEmail = email;
        targetEmail.textContent = email;
        stepRegister.classList.add('hidden');
        stepVerify.classList.remove('hidden');
        showAlert(data.message || 'Verification code sent to your email.', true);
        startCooldown(60);
        document.getElementById('otpCode').focus();
      } catch (err) {
        showAlert(err.message, false);
      } finally {
        btnRegister.disabled = false;
        btnRegister.textContent = 'Register & Send OTP';
      }
    });

    formVerify.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearAlert();
      btnVerify.disabled = true;
      btnVerify.textContent = 'Verifying...';

      const otp = document.getElementById('otpCode').value.trim();

      try {
        const res = await fetch('/api/auth/verify-otp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: currentEmail, otp })
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || data.message || 'Verification failed');
        }

        stepVerify.classList.add('hidden');
        stepSuccess.classList.remove('hidden');
        showAlert(data.message || 'Email successfully verified!', true);
      } catch (err) {
        showAlert(err.message, false);
      } finally {
        btnVerify.disabled = false;
        btnVerify.textContent = 'Verify OTP';
      }
    });

    btnResend.addEventListener('click', async () => {
      clearAlert();
      btnResend.disabled = true;

      try {
        const res = await fetch('/api/auth/resend-otp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: currentEmail })
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || data.message || 'Resend failed');
        }

        showAlert(data.message || 'New OTP sent.', true);
        startCooldown(60);
      } catch (err) {
        showAlert(err.message, false);
        btnResend.disabled = false;
      }
    });

    btnBack.addEventListener('click', () => {
      clearAlert();
      clearInterval(cooldownTimer);
      stepVerify.classList.add('hidden');
      stepRegister.classList.remove('hidden');
    });

    btnReset.addEventListener('click', () => {
      clearAlert();
      clearInterval(cooldownTimer);
      currentEmail = '';
      document.getElementById('regEmail').value = '';
      document.getElementById('regPassword').value = '';
      document.getElementById('otpCode').value = '';
      stepSuccess.classList.add('hidden');
      stepRegister.classList.remove('hidden');
    });
  </script>
</body>
</html>
"""

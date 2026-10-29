import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Dict, Any
from app.config import get_settings

logger = logging.getLogger("auth.email")
settings = get_settings()

# In-memory store for development/testing inspectability
sent_emails: List[Dict[str, Any]] = []


def send_otp_email(to_email: str, otp_code: str) -> bool:
    """
    Send OTP email to the user.
    If SMTP_HOST is configured, sends via SMTP.
    Otherwise, logs to console (Development / Local Test Mode).
    """
    subject = f"Your Verification Code: {otp_code}"
    body_text = (
        f"Hello,\n\n"
        f"Your verification code is: {otp_code}\n\n"
        f"This code will expire in {settings.OTP_EXPIRE_MINUTES} minutes.\n"
        f"If you did not request this code, please ignore this email.\n"
    )

    body_html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
          <h2 style="color: #2563eb; margin-top: 0;">Email Verification</h2>
          <p>Thank you for registering. Use the following 6-digit code to complete your verification:</p>
          <div style="background-color: #f1f5f9; padding: 16px; text-align: center; border-radius: 6px; margin: 20px 0;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #1e293b;">{otp_code}</span>
          </div>
          <p style="font-size: 14px; color: #64748b;">
            This code will expire in <strong>{settings.OTP_EXPIRE_MINUTES} minutes</strong>.
          </p>
          <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;" />
          <p style="font-size: 12px; color: #94a3b8; margin-bottom: 0;">
            If you did not request this email, please safely disregard it.
          </p>
        </div>
      </body>
    </html>
    """

    # Record in-memory for testing / auditing
    sent_emails.append({
        "to": to_email,
        "otp": otp_code,
        "subject": subject,
    })

    if not settings.SMTP_HOST:
        logger.info("[DEV EMAIL] To: %s | OTP: %s", to_email, otp_code)
        print(f"\n==================================================")
        print(f" [DEV EMAIL SIMULATOR] To: {to_email}")
        print(f" [OTP CODE]: {otp_code}")
        print(f" [EXPIRES IN]: {settings.OTP_EXPIRE_MINUTES} minutes")
        print(f"==================================================\n")
        return True

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
        msg["To"] = to_email

        msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            if settings.SMTP_USE_TLS:
                server.starttls()
            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.send_message(msg)

        logger.info("Successfully sent OTP email to %s", to_email)
        return True
    except Exception as exc:
        logger.error("Failed to send OTP email to %s: %s", to_email, exc)
        # In production, depending on policy we can raise an error or return False
        return False

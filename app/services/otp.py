from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.config import get_settings
from app.email import send_otp_email
from app.models import EmailOTP, User
from app.security import generate_otp, hash_otp, verify_otp_hash

settings = get_settings()


def ensure_utc(dt: datetime) -> datetime:
    """Ensure a datetime object is timezone-aware in UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def issue_otp(db: Session, user: User, enforce_cooldown: bool = True) -> str:
    """
    Generate and persist a 6-digit OTP for the given user, invalidating any previous OTPs.
    Rate-limits resend attempts according to OTP_RESEND_COOLDOWN_SECONDS.
    """
    now = datetime.now(timezone.utc)

    # Check for existing active OTP to enforce resend cooldown
    existing_otp = (
        db.query(EmailOTP)
        .filter(EmailOTP.user_id == user.id)
        .order_by(EmailOTP.created_at.desc())
        .first()
    )

    if existing_otp and enforce_cooldown:
        created_at_utc = ensure_utc(existing_otp.created_at)
        elapsed_seconds = (now - created_at_utc).total_seconds()
        if elapsed_seconds < settings.OTP_RESEND_COOLDOWN_SECONDS:
            remaining = int(settings.OTP_RESEND_COOLDOWN_SECONDS - elapsed_seconds)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Please wait {remaining} second(s) before requesting a new OTP.",
            )

    # Invalidate (delete) all prior OTPs for this user
    db.query(EmailOTP).filter(EmailOTP.user_id == user.id).delete()
    db.flush()

    # Generate secure 6-digit OTP and hash it with Argon2
    raw_otp = generate_otp()
    otp_hash = hash_otp(raw_otp)
    expires_at = now + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)

    new_otp_record = EmailOTP(
        user_id=user.id,
        email=user.email,
        otp_hash=otp_hash,
        expires_at=expires_at,
        attempts=0,
        created_at=now,
    )

    db.add(new_otp_record)
    db.commit()
    db.refresh(new_otp_record)

    # Send the OTP email
    sent = send_otp_email(user.email, raw_otp)
    if not sent and settings.SMTP_HOST:
        db.delete(new_otp_record)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification email. Please check your SMTP settings in .env.",
        )

    return raw_otp


def verify_otp(db: Session, email: str, otp_code: str) -> User:
    """
    Verify user submitted OTP:
    1. Matches user and active OTP record
    2. Not expired
    3. Has not exceeded maximum failed attempts
    On match: marks user as verified, deletes the OTP record.
    """
    clean_email = email.strip().lower()
    user = db.query(User).filter(User.email == clean_email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already verified.",
        )

    otp_record = (
        db.query(EmailOTP)
        .filter(EmailOTP.user_id == user.id)
        .order_by(EmailOTP.created_at.desc())
        .first()
    )

    if not otp_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active OTP found. Please request a new OTP.",
        )

    # Check if max attempts were already exceeded
    if otp_record.attempts >= settings.OTP_MAX_ATTEMPTS:
        db.delete(otp_record)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum verification attempts exceeded. Please request a new OTP.",
        )

    # Check expiration
    now = datetime.now(timezone.utc)
    if ensure_utc(otp_record.expires_at) < now:
        db.delete(otp_record)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP has expired. Please request a new OTP.",
        )

    # Verify cryptographic hash
    if not verify_otp_hash(otp_record.otp_hash, otp_code):
        otp_record.attempts += 1
        db.commit()
        remaining = settings.OTP_MAX_ATTEMPTS - otp_record.attempts
        if remaining <= 0:
            db.delete(otp_record)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid OTP. Maximum verification attempts exceeded. Please request a new OTP.",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid OTP code. {remaining} attempt(s) remaining.",
        )

    # Successfully verified: mark user verified and delete OTP
    user.is_verified = True
    db.delete(otp_record)
    db.commit()
    db.refresh(user)

    return user

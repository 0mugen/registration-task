from datetime import datetime, timedelta, timezone
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.config import get_settings
from app.database import Base
from app.email import sent_emails
from app.models import EmailOTP, User
from app.routers.auth import register, resend_user_otp, verify_user_otp
from app.schemas import ResendOTPRequest, UserRegisterRequest, VerifyOTPRequest
from app.security import (
    generate_otp,
    hash_otp,
    hash_password,
    verify_otp_hash,
    verify_password,
)
from app.services.otp import issue_otp, verify_otp

settings = get_settings()


@pytest.fixture
def db_session():
    """Create an isolated in-memory SQLite database session for each test."""
    original_smtp_host = settings.SMTP_HOST
    settings.SMTP_HOST = ""  # Force test offline/simulator mode

    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    sent_emails.clear()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)
        settings.SMTP_HOST = original_smtp_host


# ---------------------------------------------------------------------------
# Security: Passwords and OTP Hashes
# ---------------------------------------------------------------------------

def test_password_hashing():
    raw_pwd = "SuperSecretPassword123!"
    pwd_hash = hash_password(raw_pwd)

    assert pwd_hash.startswith("$argon2id$")
    assert verify_password(pwd_hash, raw_pwd) is True
    assert verify_password(pwd_hash, "WrongPassword") is False


def test_otp_generation_and_hashing():
    code = generate_otp()
    assert len(code) == 6
    assert code.isdigit()

    otp_hash = hash_otp(code)
    assert otp_hash.startswith("$argon2id$")
    assert verify_otp_hash(otp_hash, code) is True
    assert verify_otp_hash(otp_hash, "000000" if code != "000000" else "111111") is False


# ---------------------------------------------------------------------------
# Core Service: issue_otp and verify_otp
# ---------------------------------------------------------------------------

def test_issue_otp_creates_record_and_emails(db_session):
    user = User(
        email="alice@example.com",
        password_hash=hash_password("password123"),
        is_verified=False,
    )
    db_session.add(user)
    db_session.commit()

    raw_otp = issue_otp(db_session, user, enforce_cooldown=False)

    # Verify record in DB
    record = db_session.query(EmailOTP).filter(EmailOTP.user_id == user.id).first()
    assert record is not None
    assert record.email == "alice@example.com"
    assert record.attempts == 0
    assert verify_otp_hash(record.otp_hash, raw_otp) is True

    # Verify email dispatch simulator
    assert len(sent_emails) == 1
    assert sent_emails[0]["to"] == "alice@example.com"
    assert sent_emails[0]["otp"] == raw_otp


def test_verify_otp_success_marks_verified_and_deletes_otp(db_session):
    user = User(
        email="bob@example.com",
        password_hash=hash_password("password123"),
        is_verified=False,
    )
    db_session.add(user)
    db_session.commit()

    raw_otp = issue_otp(db_session, user, enforce_cooldown=False)

    verified_user = verify_otp(db_session, "bob@example.com", raw_otp)
    assert verified_user.is_verified is True

    # Check OTP record was removed
    remaining_otp = db_session.query(EmailOTP).filter(EmailOTP.user_id == user.id).first()
    assert remaining_otp is None


def test_verify_otp_invalid_code_decrements_attempts(db_session):
    user = User(
        email="charlie@example.com",
        password_hash=hash_password("password123"),
        is_verified=False,
    )
    db_session.add(user)
    db_session.commit()

    raw_otp = issue_otp(db_session, user, enforce_cooldown=False)
    wrong_otp = "999999" if raw_otp != "999999" else "888888"

    with pytest.raises(HTTPException) as exc_info:
        verify_otp(db_session, "charlie@example.com", wrong_otp)

    assert exc_info.value.status_code == 400
    assert "Invalid OTP code" in exc_info.value.detail

    record = db_session.query(EmailOTP).filter(EmailOTP.user_id == user.id).first()
    assert record.attempts == 1


def test_verify_otp_max_attempts_exceeded(db_session):
    user = User(
        email="dave@example.com",
        password_hash=hash_password("password123"),
        is_verified=False,
    )
    db_session.add(user)
    db_session.commit()

    raw_otp = issue_otp(db_session, user, enforce_cooldown=False)
    wrong_otp = "999999" if raw_otp != "999999" else "888888"

    # Fail up to max attempts
    for _ in range(settings.OTP_MAX_ATTEMPTS - 1):
        with pytest.raises(HTTPException):
            verify_otp(db_session, "dave@example.com", wrong_otp)

    # Final attempt should trigger max exceeded and delete record
    with pytest.raises(HTTPException) as exc_info:
        verify_otp(db_session, "dave@example.com", wrong_otp)

    assert exc_info.value.status_code == 400
    assert "Maximum" in exc_info.value.detail

    record = db_session.query(EmailOTP).filter(EmailOTP.user_id == user.id).first()
    assert record is None


def test_verify_otp_expired_code(db_session):
    user = User(
        email="eve@example.com",
        password_hash=hash_password("password123"),
        is_verified=False,
    )
    db_session.add(user)
    db_session.commit()

    raw_otp = issue_otp(db_session, user, enforce_cooldown=False)

    # Simulate expiration by setting expires_at to 1 minute ago
    record = db_session.query(EmailOTP).filter(EmailOTP.user_id == user.id).first()
    record.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()

    with pytest.raises(HTTPException) as exc_info:
        verify_otp(db_session, "eve@example.com", raw_otp)

    assert exc_info.value.status_code == 400
    assert "expired" in exc_info.value.detail.lower()

    # Expired OTP should be cleaned up
    remaining = db_session.query(EmailOTP).filter(EmailOTP.user_id == user.id).first()
    assert remaining is None


def test_resend_cooldown_rate_limit(db_session):
    user = User(
        email="frank@example.com",
        password_hash=hash_password("password123"),
        is_verified=False,
    )
    db_session.add(user)
    db_session.commit()

    issue_otp(db_session, user, enforce_cooldown=False)

    # Attempting to issue another OTP immediately should raise 429
    with pytest.raises(HTTPException) as exc_info:
        issue_otp(db_session, user, enforce_cooldown=True)

    assert exc_info.value.status_code == 429
    assert "Please wait" in exc_info.value.detail


def test_resend_invalidates_old_otp(db_session):
    user = User(
        email="grace@example.com",
        password_hash=hash_password("password123"),
        is_verified=False,
    )
    db_session.add(user)
    db_session.commit()

    first_otp = issue_otp(db_session, user, enforce_cooldown=False)

    # Simulate cooldown passing by setting created_at back
    record = db_session.query(EmailOTP).filter(EmailOTP.user_id == user.id).first()
    record.created_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OTP_RESEND_COOLDOWN_SECONDS + 5)
    db_session.commit()

    second_otp = issue_otp(db_session, user, enforce_cooldown=True)
    assert first_otp != second_otp

    # Attempting to verify with first_otp should fail
    with pytest.raises(HTTPException):
        verify_otp(db_session, "grace@example.com", first_otp)

    # Verifying with second_otp succeeds
    verified = verify_otp(db_session, "grace@example.com", second_otp)
    assert verified.is_verified is True


# ---------------------------------------------------------------------------
# Router Endpoints: /register, /verify-otp, /resend-otp
# ---------------------------------------------------------------------------

def test_router_register_success(db_session):
    req = UserRegisterRequest(email="heidi@example.com", password="SecretPassword123!")
    res = register(req, db=db_session)

    assert "Registration successful" in res.message
    user = db_session.query(User).filter(User.email == "heidi@example.com").first()
    assert user is not None
    assert user.is_verified is False
    assert verify_password(user.password_hash, "SecretPassword123!") is True


def test_router_register_already_verified_fails(db_session):
    user = User(
        email="verified@example.com",
        password_hash=hash_password("password123"),
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()

    req = UserRegisterRequest(email="verified@example.com", password="NewPassword123!")
    with pytest.raises(HTTPException) as exc_info:
        register(req, db=db_session)

    assert exc_info.value.status_code == 400
    assert "already registered and verified" in exc_info.value.detail.lower()


def test_router_verify_otp_flow(db_session):
    reg_req = UserRegisterRequest(email="ivan@example.com", password="Password123!")
    register(reg_req, db=db_session)

    latest_otp = sent_emails[-1]["otp"]
    verify_req = VerifyOTPRequest(email="ivan@example.com", otp=latest_otp)
    res = verify_user_otp(verify_req, db=db_session)

    assert "successfully verified" in res.message.lower()
    user = db_session.query(User).filter(User.email == "ivan@example.com").first()
    assert user.is_verified is True


def test_router_resend_otp_flow(db_session):
    reg_req = UserRegisterRequest(email="judy@example.com", password="Password123!")
    register(reg_req, db=db_session)

    # Rate limit immediately
    resend_req = ResendOTPRequest(email="judy@example.com")
    with pytest.raises(HTTPException) as exc_info:
        resend_user_otp(resend_req, db=db_session)
    assert exc_info.value.status_code == 429

    # Fast forward cooldown
    record = db_session.query(EmailOTP).filter(EmailOTP.email == "judy@example.com").first()
    record.created_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OTP_RESEND_COOLDOWN_SECONDS + 5)
    db_session.commit()

    # Now resend succeeds
    res = resend_user_otp(resend_req, db=db_session)
    assert "A new verification OTP has been sent" in res.message

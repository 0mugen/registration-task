import secrets
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# PasswordHasher configured with recommended defaults
_ph = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return _ph.hash(password)


def verify_password(hash_val: str, password: str) -> bool:
    """Verify a plaintext password against an Argon2id hash."""
    try:
        return _ph.verify(hash_val, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def generate_otp() -> str:
    """Generate a cryptographically secure 6-digit numeric OTP."""
    code = secrets.randbelow(1_000_000)
    return f"{code:06d}"


def hash_otp(otp: str) -> str:
    """Hash an OTP using Argon2id before storing in the database."""
    return _ph.hash(otp)


def verify_otp_hash(hash_val: str, otp: str) -> bool:
    """Verify an OTP against its stored Argon2id hash."""
    try:
        return _ph.verify(hash_val, otp)
    except (VerifyMismatchError, InvalidHashError):
        return False

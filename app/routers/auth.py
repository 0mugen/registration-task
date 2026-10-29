from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
from app.schemas import MessageResponse, ResendOTPRequest, UserRegisterRequest, VerifyOTPRequest
from app.security import hash_password
from app.services.otp import issue_otp, verify_otp

router = APIRouter(prefix="", tags=["Auth"])


@router.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
def register(payload: UserRegisterRequest, db: Session = Depends(get_db)):
    """
    Register a new user:
    - Normalizes email
    - Checks if email is already taken and verified
    - Creates user record with is_verified = False
    - Hashes password using Argon2id
    - Issues a 6-digit OTP and emails it
    """
    clean_email = payload.email.strip().lower()

    existing_user = db.query(User).filter(User.email == clean_email).first()
    if existing_user:
        if existing_user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is already registered and verified.",
            )
        # Unverified user registering again: update password and reissue OTP
        existing_user.password_hash = hash_password(payload.password)
        db.commit()
        db.refresh(existing_user)
        issue_otp(db, existing_user, enforce_cooldown=True)
        return MessageResponse(
            message="User account pending verification. A fresh OTP has been sent to your email."
        )

    # Create new user
    new_user = User(
        email=clean_email,
        password_hash=hash_password(payload.password),
        is_verified=False,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Issue initial OTP
    issue_otp(db, new_user, enforce_cooldown=False)

    return MessageResponse(
        message="Registration successful. A verification code has been sent to your email."
    )


@router.post(
    "/verify-otp",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify OTP",
)
def verify_user_otp(payload: VerifyOTPRequest, db: Session = Depends(get_db)):
    """
    Verify the 6-digit OTP for the given email address.
    Upon verification:
    - Sets user.is_verified = True
    - Deletes the active OTP record
    """
    clean_email = payload.email.strip().lower()
    verify_otp(db, clean_email, payload.otp.strip())
    return MessageResponse(message="Email successfully verified.")


@router.post(
    "/resend-otp",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Resend verification OTP",
)
def resend_user_otp(payload: ResendOTPRequest, db: Session = Depends(get_db)):
    """
    Resend an OTP code to the specified email:
    - Subject to cooldown rate limiting (e.g. 60 seconds)
    - Invalidate prior OTP
    """
    clean_email = payload.email.strip().lower()
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

    issue_otp(db, user, enforce_cooldown=True)
    return MessageResponse(message="A new verification OTP has been sent to your email.")

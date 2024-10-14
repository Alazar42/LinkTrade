from datetime import datetime, timezone
import os
import time
from typing import Dict, List
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import jwt
from app.models import User, UserResponse, UserRole
from cryptography.hazmat.backends import default_backend
from io import BytesIO
import base64
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

def user_helper(user: Dict) -> UserResponse:
    """Transform user data dictionary into a simplified dictionary."""
    return UserResponse(
        name=user.get("name"),
        email=user.get("email"),
        role=user.get("role"),
        phone_number=user.get("phone_number"),
        address=user.get("address"),
        profile_image=user.get("profile_image"),
        company_name=user.get("company_name"),
        created_at=user.get("created_at"),
        updated_at=user.get("updated_at"),
    )



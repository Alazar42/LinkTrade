from datetime import datetime, timedelta, timezone
from bson import ObjectId
from fastapi.security import OAuth2PasswordBearer
from typing import Optional, Union
from fastapi import Depends, logger
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException
from jose import JWTError, jwt
from pydantic import BaseModel
from config.database import db


import os
from dotenv import load_dotenv
load_dotenv()

SECRET_KEY = str(os.getenv("SECRET_KEY"))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Define OAuth2PasswordBearer instance
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/login")

class TokenData(BaseModel):
    phone_number: str

def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        phone_number: str = str(payload.get("sub"))
        if phone_number is None:
            return None
        token_data = TokenData(phone_number=phone_number)
    except JWTError:
        return None
    return token_data.phone_number


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        # Log or handle the exception as needed
        print(f"Password verification error: {e}")
        return False

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def decode_jwt(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

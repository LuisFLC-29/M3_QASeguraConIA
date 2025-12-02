import time
from typing import Optional, Dict
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
from .schemas import UserCreate

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_SECRET = "CHANGE_THIS_SECRET_TO_ENV"  # usa env var en CI/prod
JWT_ALGO = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Simulated user table (replace with DB)
_users: Dict[str, Dict] = {}

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_user(user: UserCreate) -> Dict:
    if user.username in _users or any(u["email"] == user.email for u in _users.values()):
        raise ValueError("Usuario o email ya existe")
    hashed = hash_password(user.password)
    user_record = {
        "username": user.username,
        "email": user.email,
        "password_hash": hashed,
        "created_at": time.time()
    }
    _users[user.username] = user_record
    return user_record

def authenticate(username_or_email: str, password: str) -> Optional[Dict]:
    # buscar por username o email
    user = None
    if username_or_email in _users:
        user = _users[username_or_email]
    else:
        for u in _users.values():
            if u["email"] == username_or_email:
                user = u
                break
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user

def create_access_token(subject: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode = {"sub": subject, "exp": expire}
    token = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGO)
    return token

def decode_token(token: str) -> Optional[Dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.PyJWTError:
        return None

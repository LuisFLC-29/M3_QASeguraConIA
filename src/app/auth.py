from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from .schemas import UserCreate, UserInDB, TokenData, UserBase

# Clave de ejemplo SOLO para entorno educativo: cámbiala en tu repo real
SECRET_KEY = "CHANGE_THIS_SECRET_KEY_USE_ENV_VAR_IN_REAL_PROJECTS"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# "Base de datos" en memoria solo para demo
_fake_users_db: Dict[str, UserInDB] = {}


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_user(user_in: UserCreate) -> UserBase:
    if user_in.email in _fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists",
        )
    hashed = get_password_hash(user_in.password)
    user_db = UserInDB(email=user_in.email, full_name=user_in.full_name, hashed_password=hashed)
    _fake_users_db[user_in.email] = user_db
    return UserBase(email=user_db.email, full_name=user_db.full_name)


def authenticate_user(email: str, password: str) -> Optional[UserInDB]:
    user = _fake_users_db.get(email)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserBase:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        sub: str = payload.get("sub")
        if sub is None:
            raise credentials_exception
        token_data = TokenData(sub=sub)
    except JWTError:
        raise credentials_exception

    user = _fake_users_db.get(token_data.sub)
    if user is None:
        raise credentials_exception

    return UserBase(email=user.email, full_name=user.full_name)

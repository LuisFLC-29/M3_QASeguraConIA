from datetime import timedelta

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm

from .auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    authenticate_user,
    create_access_token,
    create_user,
    get_current_user,
)
from .rate_limit import login_rate_limiter
from .schemas import LoginRequest, Token, UserBase, UserCreate

app = FastAPI(title="Auth API Secure IA")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/register", response_model=UserBase, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate):
    """
    Registro de usuario con validación de schema y hash de contraseña.
    """
    return create_user(user_in)


@app.post("/auth/login", response_model=Token, dependencies=[Depends(login_rate_limiter)])
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login con OAuth2PasswordRequestForm (username = email).
    Rate limiting aplicado a este endpoint.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return Token(access_token=access_token)


@app.post("/auth/login-json", response_model=Token, dependencies=[Depends(login_rate_limiter)])
def login_json(payload: LoginRequest):
    """
    Variante JSON del login usada en pruebas de seguridad (SQLi, XSS, etc.).
    """
    user = authenticate_user(payload.email, payload.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return Token(access_token=access_token)


@app.get("/users/me", response_model=UserBase)
async def read_users_me(current_user: UserBase = Depends(get_current_user)):
    """
    Endpoint protegido que usa JWT.
    """
    return current_user


@app.exception_handler(Exception)
async def generic_exception_handler(_, exc: Exception):
    # handler simple para evitar filtrar trazas en respuestas
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )

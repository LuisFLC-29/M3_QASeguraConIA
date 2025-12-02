from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, constr


class UserBase(BaseModel):
    email: EmailStr
    full_name: constr(
        min_length=1,
        max_length=50,
        pattern=r"^[^<>]*$"  # Previene < y > para mitigar XSS básico
    ) = Field(..., description="Nombre sin caracteres < o >")


class UserCreate(UserBase):
    password: constr(min_length=8)


class UserInDB(UserBase):
    hashed_password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    sub: EmailStr
    exp: datetime | None = None

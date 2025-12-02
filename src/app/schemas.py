from pydantic import BaseModel, Field, EmailStr, constr

PasswordStr = constr(min_length=8, max_length=128)

class UserCreate(BaseModel):
    username: constr(min_length=3, max_length=30, regex=r'^[a-zA-Z0-9_.-]+$') = Field(..., description="Alfanumérico, guiones, underscore")
    email: EmailStr
    password: PasswordStr

class UserLogin(BaseModel):
    username_or_email: str = Field(..., description="username o email")
    password: str = Field(..., min_length=1)

from datetime import timedelta

from jose import jwt

from app import auth
from app.schemas import UserCreate


def test_password_hash_and_verify():
    password = "SuperSecure123!"
    hashed = auth.get_password_hash(password)
    assert hashed != password
    assert auth.verify_password(password, hashed)
    assert not auth.verify_password("wrong", hashed)


def test_create_and_authenticate_user():
    user_in = UserCreate(
        email="user@example.com",
        full_name="Test User",
        password="Password123!",
    )
    created = auth.create_user(user_in)
    assert created.email == user_in.email

    user = auth.authenticate_user(user_in.email, user_in.password)
    assert user is not None
    assert user.email == user_in.email

    assert auth.authenticate_user(user_in.email, "WrongPassword") is None


def test_create_access_token_contains_sub():
    data = {"sub": "user@example.com"}
    token = auth.create_access_token(data, expires_delta=timedelta(minutes=5))
    decoded = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
    assert decoded["sub"] == data["sub"]

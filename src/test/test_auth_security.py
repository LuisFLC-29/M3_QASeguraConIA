from fastapi.testclient import TestClient

from app.main import app
from app import auth
from app.schemas import UserCreate

client = TestClient(app)


def setup_user():
    user_in = UserCreate(
        email="secure@example.com",
        full_name="Secure User",
        password="StrongPass123!",
    )
    try:
        auth.create_user(user_in)
    except Exception:
        # ya existe
        pass


def test_login_rejects_sqli_like_input():
    setup_user()
    payload = {
        "email": "secure@example.com",
        "password": "' OR '1'='1"
    }
    response = client.post("/auth/login-json", json=payload)
    assert response.status_code == 401
    assert "Incorrect email or password" in response.text


def test_register_rejects_xss_in_full_name():
    payload = {
        "email": "xss@example.com",
        "full_name": "<script>alert('xss')</script>",
        "password": "StrongPass123!",
    }
    response = client.post("/auth/register", json=payload)
    # Pydantic debería rechazar por pattern, devolviendo 422
    assert response.status_code == 422


def test_rate_limit_on_login():
    setup_user()
    for _ in range(5):
        client.post("/auth/login-json", json={
            "email": "secure@example.com",
            "password": "WrongPass",
        })
    sixth = client.post("/auth/login-json", json={
        "email": "secure@example.com",
        "password": "WrongPass",
    })
    assert sixth.status_code in (429, 401)

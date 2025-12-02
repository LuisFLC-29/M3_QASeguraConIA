from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_full_auth_flow_register_login_me():
    # 1) registro
    register_payload = {
        "email": "integration@example.com",
        "full_name": "Integration User",
        "password": "StrongPass123!",
    }
    r_reg = client.post("/auth/register", json=register_payload)
    assert r_reg.status_code in (201, 400)  # 400 si ya existe

    # 2) login (OAuth2PasswordRequestForm usa x-www-form-urlencoded)
    form = {
        "username": "integration@example.com",
        "password": "StrongPass123!",
    }
    r_login = client.post("/auth/login", data=form)
    assert r_login.status_code == 200
    token = r_login.json()["access_token"]

    # 3) acceso a endpoint protegido
    headers = {"Authorization": f"Bearer {token}"}
    r_me = client.get("/users/me", headers=headers)
    assert r_me.status_code == 200
    data = r_me.json()
    assert data["email"] == "integration@example.com"

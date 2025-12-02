import pytest
from app.auth import _users, create_user
from app.schemas import UserCreate
from app.main import app
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_sql_injection_like_username_rejected():
    _users.clear()
    async with AsyncClient(app=app, base_url="http://test") as ac:
        payload = {
            "username": "alice'; DROP TABLE users; --",
            "email": "sqlex@ex.com",
            "password": "Password789"
        }
        r = await ac.post("/register", json=payload)
        # schema regex should reject this invalid username -> 422
        assert r.status_code == 422 or r.status_code == 400

@pytest.mark.asyncio
async def test_xss_in_email_rejected():
    _users.clear()
    async with AsyncClient(app=app, base_url="http://test") as ac:
        payload = {
            "username": "charlie",
            "email": "<script>alert(1)</script>@ex.com",
            "password": "Password789"
        }
        r = await ac.post("/register", json=payload)
        # invalid email should be rejected
        assert r.status_code in (422, 400)

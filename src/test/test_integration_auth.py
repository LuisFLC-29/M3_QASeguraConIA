import pytest
from httpx import AsyncClient
from app.main import app
from app.auth import _users

@pytest.mark.asyncio
async def test_register_and_login():
    _users.clear()
    async with AsyncClient(app=app, base_url="http://test") as ac:
        r = await ac.post("/register", json={
            "username": "bob",
            "email": "bob@example.com",
            "password": "Password456"
        })
        assert r.status_code == 200
        # login
        r2 = await ac.post("/login", json={
            "username_or_email": "bob",
            "password": "Password456"
        })
        assert r2.status_code == 200
        data = r2.json()
        assert "access_token" in data

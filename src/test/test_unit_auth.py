import pytest
from app.auth import hash_password, verify_password, create_user, authenticate, _users
from app.schemas import UserCreate

def test_hash_and_verify():
    pw = "My$ecret123"
    h = hash_password(pw)
    assert verify_password(pw, h) is True
    assert verify_password("wrong", h) is False

def test_create_and_authenticate_user():
    # limpiar store
    _users.clear()
    u = UserCreate(username="alice", email="alice@example.com", password="Password123")
    rec = create_user(u)
    assert rec["username"] == "alice"
    # success auth by username
    auth = authenticate("alice", "Password123")
    assert auth is not None
    # success auth by email
    auth2 = authenticate("alice@example.com", "Password123")
    assert auth2 is not None
    # fail wrong password
    assert authenticate("alice", "badpass") is None

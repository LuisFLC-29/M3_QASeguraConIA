from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from .schemas import UserCreate, UserLogin
from .auth import create_user, authenticate, create_access_token
from .deps import limiter

app = FastAPI(title="Auth Challenge")

# Register rate limit handler
@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Too many requests"})

@app.post("/register")
@limiter.limit("5/minute")
async def register(user: UserCreate):
    try:
        rec = create_user(user)
        return {"username": rec["username"], "email": rec["email"]}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/login")
@limiter.limit("10/minute")
async def login(payload: UserLogin):
    user = authenticate(payload.username_or_email, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(user["username"])
    return {"access_token": token, "token_type": "bearer"}

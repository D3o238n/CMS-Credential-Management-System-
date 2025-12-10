from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
import jwt
import os

app = FastAPI(title="Authentication Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET", "jwt-secret")
JWT_EXPIRATION = int(os.getenv("JWT_EXPIRATION", "3600"))

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: str = "user"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    user_id: int
    email: str
    role: str
    full_name: str

def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        conn.close()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_token(user_id: int, email: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "role": role,
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXPIRATION),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "auth-service"}

@app.post("/api/auth/register", response_model=TokenResponse)
def register(user: UserRegister):
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    cursor.execute("SELECT id FROM users WHERE email = %s", (user.email,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")
    
    password_hash = hash_password(user.password)
    
    cursor.execute("""
        INSERT INTO users (email, password_hash, full_name, role)
        VALUES (%s, %s, %s, %s)
        RETURNING id, email, full_name, role, created_at
    """, (user.email, password_hash, user.full_name, user.role))
    
    new_user = cursor.fetchone()
    conn.commit()
    conn.close()
    
    token = create_token(new_user['id'], new_user['email'], new_user['role'])
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": JWT_EXPIRATION,
        "user_id": new_user['id'],
        "email": new_user['email'],
        "role": new_user['role'],
        "full_name": new_user['full_name']
    }

@app.post("/api/auth/login", response_model=TokenResponse)
def login(credentials: UserLogin):
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    cursor.execute("""
        SELECT id, email, password_hash, full_name, role
        FROM users
        WHERE email = %s
    """, (credentials.email,))
    
    user = cursor.fetchone()
    
    if not user or not verify_password(credentials.password, user['password_hash']):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user['id'],))
    conn.commit()
    conn.close()
    
    token = create_token(user['id'], user['email'], user['role'])
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": JWT_EXPIRATION,
        "user_id": user['id'],
        "email": user['email'],
        "role": user['role'],
        "full_name": user['full_name']
    }

@app.get("/api/auth/verify")
def verify_token_endpoint(authorization: str):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    
    token = authorization.split(" ")[1]
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return {"valid": True, "user": payload}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
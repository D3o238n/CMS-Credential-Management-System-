from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from cryptography.fernet import Fernet
import os
import jwt
import json

app = FastAPI(title="Secrets Management Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
JWT_SECRET = os.getenv("JWT_SECRET", "jwt-secret")

# ИСПРАВЛЕНО: правильная инициализация Fernet
if SECRET_KEY:
    cipher = Fernet(SECRET_KEY.encode() if isinstance(SECRET_KEY, str) else SECRET_KEY)
else:
    cipher = Fernet(Fernet.generate_key())

class SecretCreate(BaseModel):
    name: str
    type: str
    value: str
    description: Optional[str] = None
    tags: Optional[List[str]] = []

class SecretUpdate(BaseModel):
    value: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None

class SecretResponse(BaseModel):
    id: int
    name: str
    type: str
    description: Optional[str]
    tags: List[str]
    created_at: datetime
    updated_at: datetime
    version: int
    owner_email: str

def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        conn.close()

def verify_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def encrypt_value(value: str) -> str:
    return cipher.encrypt(value.encode()).decode()

def decrypt_value(encrypted_value: str) -> str:
    return cipher.decrypt(encrypted_value.encode()).decode()

def parse_tags(tags):
    if tags is None:
        return []
    if isinstance(tags, (list, tuple)):
        return list(tags)
    if isinstance(tags, str):
        try:
            return json.loads(tags)
        except:
            return [tags]
    return []

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "secrets-service"}

@app.post("/api/secrets", response_model=SecretResponse)
def create_secret(secret: SecretCreate, user=Depends(verify_token), db=Depends(get_db)):
    # USER не может создавать секреты (только читать)
    if user['role'] == 'user':
        raise HTTPException(status_code=403, detail="Users cannot create secrets. Contact your administrator.")
    
    cursor = db.cursor(cursor_factory=RealDictCursor)
    encrypted_value = encrypt_value(secret.value)
    
    cursor.execute("""
        INSERT INTO secrets (name, type, encrypted_value, description, tags, owner_id, version)
        VALUES (%s, %s, %s, %s, %s, %s, 1)
        RETURNING id, name, type, description, tags, created_at, updated_at, version
    """, (secret.name, secret.type, encrypted_value, secret.description, json.dumps(secret.tags), user['user_id']))
    
    result = cursor.fetchone()
    db.commit()
    log_audit(user['user_id'], 'CREATE', result['id'], user['email'])
    
    return {**result, "tags": parse_tags(result['tags']), "owner_email": user['email']}

@app.get("/api/secrets", response_model=List[SecretResponse])
def list_secrets(user=Depends(verify_token), db=Depends(get_db)):
    cursor = db.cursor(cursor_factory=RealDictCursor)
    
    # ADMIN видит ВСЕ секреты, остальные - только свои
    if user['role'] == 'admin':
        cursor.execute("""
            SELECT s.*, u.email as owner_email
            FROM secrets s
            JOIN users u ON s.owner_id = u.id
            WHERE s.deleted_at IS NULL
            ORDER BY s.updated_at DESC
        """)
    else:
        cursor.execute("""
            SELECT s.*, u.email as owner_email
            FROM secrets s
            JOIN users u ON s.owner_id = u.id
            WHERE s.owner_id = %s AND s.deleted_at IS NULL
            ORDER BY s.updated_at DESC
        """, (user['user_id'],))
    
    results = cursor.fetchall()
    return [{"tags": parse_tags(row['tags']), **row} for row in results]

@app.get("/api/secrets/{secret_id}")
def get_secret(secret_id: int, show_value: bool = False, user=Depends(verify_token), db=Depends(get_db)):
    cursor = db.cursor(cursor_factory=RealDictCursor)
    
    # ADMIN может видеть любой секрет, остальные - только свои
    if user['role'] == 'admin':
        cursor.execute("""
            SELECT s.*, u.email as owner_email
            FROM secrets s
            JOIN users u ON s.owner_id = u.id
            WHERE s.id = %s AND s.deleted_at IS NULL
        """, (secret_id,))
    else:
        cursor.execute("""
            SELECT s.*, u.email as owner_email
            FROM secrets s
            JOIN users u ON s.owner_id = u.id
            WHERE s.id = %s AND s.owner_id = %s AND s.deleted_at IS NULL
        """, (secret_id, user['user_id']))
    
    result = cursor.fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="Secret not found")
    
    log_audit(user['user_id'], 'VIEW', secret_id, user['email'])
    
    response = {**result, "tags": parse_tags(result['tags'])}
    response['value'] = decrypt_value(result['encrypted_value']) if show_value else "••••••••••••"
    del response['encrypted_value']
    
    return response

@app.put("/api/secrets/{secret_id}")
def update_secret(secret_id: int, secret_update: SecretUpdate, user=Depends(verify_token), db=Depends(get_db)):
    cursor = db.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM secrets WHERE id = %s AND owner_id = %s AND deleted_at IS NULL", (secret_id, user['user_id']))
    
    existing = cursor.fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Secret not found")
    
    cursor.execute("INSERT INTO secret_versions (secret_id, version, encrypted_value, updated_by) VALUES (%s, %s, %s, %s)",
                  (secret_id, existing['version'], existing['encrypted_value'], user['user_id']))
    
    updates, params = [], []
    if secret_update.value:
        updates.extend(["encrypted_value = %s", "version = version + 1"])
        params.append(encrypt_value(secret_update.value))
    if secret_update.description is not None:
        updates.append("description = %s")
        params.append(secret_update.description)
    if secret_update.tags is not None:
        updates.append("tags = %s")
        params.append(json.dumps(secret_update.tags))
    
    updates.append("updated_at = NOW()")
    params.extend([secret_id, user['user_id']])
    
    cursor.execute(f"UPDATE secrets SET {', '.join(updates)} WHERE id = %s AND owner_id = %s RETURNING *", params)
    result = cursor.fetchone()
    db.commit()
    log_audit(user['user_id'], 'UPDATE', secret_id, user['email'])
    
    return {"message": "Secret updated successfully", "new_version": result['version']}

@app.delete("/api/secrets/{secret_id}")
def delete_secret(secret_id: int, user=Depends(verify_token), db=Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("UPDATE secrets SET deleted_at = NOW() WHERE id = %s AND owner_id = %s AND deleted_at IS NULL", (secret_id, user['user_id']))
    
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Secret not found")
    
    db.commit()
    log_audit(user['user_id'], 'DELETE', secret_id, user['email'])
    return {"message": "Secret deleted successfully"}

@app.get("/api/secrets/{secret_id}/versions")
def get_secret_versions(secret_id: int, user=Depends(verify_token), db=Depends(get_db)):
    cursor = db.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT id FROM secrets WHERE id = %s AND owner_id = %s AND deleted_at IS NULL", (secret_id, user['user_id']))
    
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="Secret not found")
    
    cursor.execute("""
        SELECT sv.*, u.email as updated_by_email
        FROM secret_versions sv
        JOIN users u ON sv.updated_by = u.id
        WHERE sv.secret_id = %s
        ORDER BY sv.version DESC
    """, (secret_id,))
    
    return cursor.fetchall()

@app.post("/api/secrets/{secret_id}/rotate")
def rotate_secret(secret_id: int, user=Depends(verify_token), db=Depends(get_db)):
    import secrets, string
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    new_password = ''.join(secrets.choice(alphabet) for _ in range(20))
    
    secret_update = SecretUpdate(value=new_password)
    update_secret(secret_id, secret_update, user, db)
    log_audit(user['user_id'], 'ROTATE', secret_id, user['email'])
    
    return {"message": "Secret rotated successfully", "new_value": new_password}

def log_audit(user_id: int, action: str, secret_id: int, user_email: str):
    try:
        import requests
        requests.post("http://audit-service:8002/api/audit",
            json={"user_id": user_id, "user_email": user_email, "action": action, "secret_id": secret_id, "timestamp": datetime.now().isoformat()},
            timeout=2)
    except:
        pass
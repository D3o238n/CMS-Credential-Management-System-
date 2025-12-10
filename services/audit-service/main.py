from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List
import psycopg2
from psycopg2.extras import RealDictCursor
import os

app = FastAPI(title="Audit Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.getenv("DATABASE_URL")

class AuditLogCreate(BaseModel):
    user_id: int
    user_email: str
    action: str
    secret_id: int
    timestamp: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "audit-service"}

@app.post("/api/audit")
def create_audit_log(log: AuditLogCreate):
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO audit_logs (user_id, user_email, action, secret_id, ip_address, user_agent)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (log.user_id, log.user_email, log.action, log.secret_id, log.ip_address, log.user_agent))
    
    conn.commit()
    conn.close()
    
    try:
        with open("/app/logs/audit.log", "a") as f:
            f.write(f"{datetime.now().isoformat()} | {log.user_email} | {log.action} | Secret ID: {log.secret_id}\n")
    except:
        pass
    
    return {"message": "Audit log created"}

@app.get("/api/audit")
def get_audit_logs(
    action: Optional[str] = Query(None),
    user_email: Optional[str] = Query(None),
    secret_id: Optional[int] = Query(None),
    limit: int = Query(100, le=1000)
):
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    query = "SELECT * FROM audit_logs WHERE 1=1"
    params = []
    
    if action:
        query += " AND action = %s"
        params.append(action)
    
    if user_email:
        query += " AND user_email = %s"
        params.append(user_email)
    
    if secret_id:
        query += " AND secret_id = %s"
        params.append(secret_id)
    
    query += f" ORDER BY created_at DESC LIMIT {limit}"
    
    cursor.execute(query, params)
    results = cursor.fetchall()
    conn.close()
    
    return results
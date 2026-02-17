from fastapi import FastAPI, WebSocket, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import os
import redis
from celery import Celery
from elasticsearch import Elasticsearch
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

app = FastAPI()

# Config
SECRET_KEY = os.environ.get("JWT_SECRET", "changeme")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Celery
celery_app = Celery('tasks', broker=os.environ.get('CELERY_BROKER_URL'))

# Elasticsearch
es = Elasticsearch(hosts=[os.environ.get('ELASTICSEARCH_URL')])

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = None # Simplified for now

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    password: str

# Mock user db (in memory for this task, better to use DB)
fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": "$2b$12$upVRLCMFcmKFklvJwh8jYeJr9sYr95hLA4ElWnIQue9jZlXa3hgDW"
    }
}

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: User):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user['hashed_password']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user['username']})
    return {"access_token": access_token, "token_type": "bearer"}

# Scan Endpoint
class ScanRequest(BaseModel):
    target: str

@app.post("/scan")
async def start_scan(scan_req: ScanRequest):
    # validate target (IP or domain)
    task = celery_app.send_task('tasks.scan_target', args=[scan_req.target])
    return {"message": "Scan started", "task_id": task.id}

# Search Endpoint
@app.get("/search")
async def search(q: str):
    res = es.search(index="shodan_scan", body={"query": {"query_string": {"query": q}}})
    return res['hits']['hits']

# Live Monitor (WebSocket)
# In a real app, Worker would publish to Redis, API subscribes.
# Here, we'll implement a basic mock stream or connect to Redis.
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # Receive message (e.g. subscribe to topic)
            data = await websocket.receive_text()
            # Push updates (mock for now)
            await websocket.send_text(f"Scanning update for {data}...")
    except Exception:
        pass

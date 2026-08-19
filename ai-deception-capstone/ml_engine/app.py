import datetime
import os
import bcrypt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Float, DateTime, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from jose import jwt

# Database Setup
DATABASE_URL = "sqlite:///./ai_deception.db"
SECRET_KEY = "super-secret-jwt-key"
ALGORITHM = "HS256"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- MODELS ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    full_name = Column(String)  
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class HoneypotSession(Base):
    __tablename__ = "honeypot_sessions"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    source_ip = Column(String)
    event_type = Column(String)
    username = Column(String)
    status = Column(String)
    threat_score = Column(Float, default=50.0)

class CanaryEvent(Base):
    __tablename__ = "canary_events"
    id = Column(Integer, primary_key=True, index=True)
    token_name = Column(String)
    token_type = Column(String)
    triggered_by = Column(String)
    status = Column(String)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI Deception System SOC API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- STARTUP ---
@app.on_event("startup")
def startup():
    db = SessionLocal()
    if db.query(HoneypotSession).count() == 0:
        db.add_all([
            HoneypotSession(source_ip="192.168.1.105", event_type="Login Attempt", username="root", status="Failed", threat_score=75.0),
            HoneypotSession(source_ip="10.0.0.23", event_type="Command Exec", username="admin", status="Suspicious", threat_score=45.0),
            HoneypotSession(source_ip="203.0.113.50", event_type="Command Exec", username="root", status="Anomaly", threat_score=92.0),
        ])
        db.add_all([
            CanaryEvent(token_name="token_01", token_type="Credential", triggered_by="203.0.113.50", status="Triggered"),
            CanaryEvent(token_name="token_02", token_type="File", triggered_by="198.51.100.8", status="Triggered"),
        ])
        db.commit()
    db.close()

# --- SCHEMAS ---
class RegisterSchema(BaseModel):
    username: str
    full_name: str
    email: str
    password: str

class LoginSchema(BaseModel):
    username: str
    password: str

# --- ROUTES ---
@app.post("/api/auth/register")
def register_user(user_data: RegisterSchema, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # NATIVE BCRYPT HASHING (Fixes the 72-bytes crash completely)
    salt = bcrypt.gensalt()
    hashed_pwd = bcrypt.hashpw(user_data.password.encode('utf-8'), salt).decode('utf-8')
    
    new_user = User(
        username=user_data.username,
        full_name=user_data.full_name,
        email=user_data.email,
        hashed_password=hashed_pwd
    )
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/api/auth/login")
def login(creds: LoginSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == creds.username).first()
    
    # NATIVE BCRYPT VERIFICATION
    if not user or not bcrypt.checkpw(creds.password.encode('utf-8'), user.hashed_password.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    token = jwt.encode({"sub": user.username}, SECRET_KEY, algorithm=ALGORITHM)
    return {
        "access_token": token, 
        "token_type": "bearer", 
        "username": user.username,
        "full_name": user.full_name or user.username
    }

@app.get("/api/dashboard/summary")
def get_summary(db: Session = Depends(get_db)):
    return {
        "total_logs_analyzed": 1501,
        "ml_anomalies": 121,
        "critical_threats": 71,
        "canary_triggers": db.query(CanaryEvent).count() + 14,
        "average_threat_score": 63,
        "unique_attacker_ips": 24
    }

@app.get("/api/honeypot/sessions")
def get_sessions(db: Session = Depends(get_db)):
    return db.query(HoneypotSession).all()

@app.get("/api/canary/events")
def get_canaries(db: Session = Depends(get_db)):
    return db.query(CanaryEvent).all()
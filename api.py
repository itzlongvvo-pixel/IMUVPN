from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, List
import secrets

app = FastAPI(title="imuVPN API", version="0.1.0")

# CORS: open during dev; lock down later to your Netlify domain
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # later: ["https://YOUR-SITE.netlify.app"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

USERS: Dict[str, Dict] = {}
SESSIONS: Dict[str, Dict] = {}
CONFIGS: Dict[str, List[Dict]] = {}

class SignupBody(BaseModel):
    email: str
    password: str   # NOTE: plain text for demo; hash in real prod

class LoginBody(BaseModel):
    email: str
    password: str

class CreateConfigBody(BaseModel):
    device_name: str
    location: str  # e.g., "sgp-1"

class CheckoutBody(BaseModel):
    priceId: str

def auth(authorization: Optional[str] = Header(None)):
    if not authorization or authorization not in SESSIONS:
        raise HTTPException(401, "unauthorized")
    return SESSIONS[authorization]

@app.get("/")
def root():
    return {"ok": True, "service": "imuVPN API"}

@app.post("/auth/signup")
def signup(body: SignupBody):
    if body.email in USERS:
        raise HTTPException(409, "email_exists")
    USERS[body.email] = {"password": body.password, "active": True}
    return {"ok": True}

@app.post("/auth/login")
def login(body: LoginBody):
    user = USERS.get(body.email)
    if not user or user["password"] != body.password:
        raise HTTPException(401, "bad_credentials")
    token = secrets.token_hex(16)
    SESSIONS[token] = {"email": body.email}
    return {"token": token}

@app.post("/wireguard/configs")
def create_config(body: CreateConfigBody, user=Depends(auth)):
    private_key = secrets.token_hex(16)
    public_key = secrets.token_hex(16)
    peer_ip = f"10.8.{secrets.randbelow(200)}.{secrets.randbelow(200)}/32"
    config = f"""[Interface]
PrivateKey = {private_key}
Address = {peer_ip}
DNS = 1.1.1.1

[Peer]
PublicKey = {public_key}
Endpoint = wg.{body.location}.imuvpn.example:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    email = user["email"]
    CONFIGS.setdefault(email, []).append({
        "name": body.device_name,
        "location": body.location,
        "config": config
    })
    return {"device": body.device_name, "config": config}

@app.get("/wireguard/configs")
def list_configs(user=Depends(auth)):
    return CONFIGS.get(user["email"], [])

@app.post("/billing/checkout")
def checkout(body: CheckoutBody):
    # Placeholder Stripe mapping
    price_map = {
        "price_monthly": "price_monthly_id_here",
        "price_yearly":  "price_yearly_id_here",
        "price_family":  "price_family_id_here",
    }
    price_id = price_map.get(body.priceId, "price_unknown")
    return {"url": f"https://example.com/checkout?price={price_id}"}

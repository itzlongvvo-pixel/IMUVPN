from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, List
import secrets
import os
import stripe

# --- Stripe setup ---
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")

# Optional debug - keep for now, remove later if you want
if not stripe.api_key:
    print("DEBUG: STRIPE_SECRET_KEY is MISSING or EMPTY in environment")
else:
    print("DEBUG: Stripe key loaded, length:", len(stripe.api_key))

# --- App setup ---
app = FastAPI(title="imuVPN API", version="0.2.0")

# CORS: open during dev; lock down later to your Netlify domain
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # later: ["https://imuvpn.netlify.app"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- In-memory stores (demo only) ---
USERS: Dict[str, Dict] = {}      # email -> {"password": ..., "active": bool}
SESSIONS: Dict[str, Dict] = {}   # token -> {"email": ...}
CONFIGS: Dict[str, List[Dict]] = {}  # email -> [ {name, location, config} ]


# --- Models ---


class SignupBody(BaseModel):
    email: str
    password: str   # NOTE: plain text for demo; hash in real prod


class LoginBody(BaseModel):
    email: str
    password: str


class CreateConfigBody(BaseModel):
    device_name: str
    location: str  # e.g., "us-la-2"


class CheckoutBody(BaseModel):
    priceId: str  # "price_monthly" | "price_yearly" | "price_family"


class AdminOverview(BaseModel):
    total_users: int
    active_sessions: int
    total_devices: int


# --- Auth dependency ---


def auth(authorization: Optional[str] = Header(None)):
    """
    Simple token-based auth using SESSIONS dict.
    In prod you'd use JWT + a real DB.
    """
    if not authorization or authorization not in SESSIONS:
        raise HTTPException(401, "unauthorized")
    return SESSIONS[authorization]


# --- Health ---


@app.get("/")
def root():
    return {"ok": True, "service": "imuVPN API", "version": "0.2.0"}


# --- Auth routes ---


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


@app.get("/auth/me")
def me(user=Depends(auth)):
    email = user["email"]
    data = USERS.get(email, {})
    return {"email": email, "active": data.get("active", False)}


# --- WireGuard config routes (still mock, but structured) ---


@app.post("/wireguard/configs")
def create_config(body: CreateConfigBody, user=Depends(auth)):
    """
    For now this generates a fake WireGuard config.
    Later we will call real VPN servers here.
    """
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
    CONFIGS.setdefault(email, []).append(
        {
            "name": body.device_name,
            "location": body.location,
            "config": config,
        }
    )
    return {"device": body.device_name, "config": config}


@app.get("/wireguard/configs")
def list_configs(user=Depends(auth)):
    return CONFIGS.get(user["email"], [])


# --- Stripe Checkout mapping ---


PRICE_LOOKUP = {
    "price_monthly": "price_1ST0aPA2orsFpuy3FeqNH1Ti",   # Monthly
    "price_yearly":  "price_1ST0bbA2orsFpuy3yg1VLRLX",   # Yearly
    "price_family":  "price_1ST0cRA2orsFpuy3y2KmWWg0",   # Family
}


@app.post("/billing/checkout")
def checkout(body: CheckoutBody, user=Depends(auth)):
    stripe_price = PRICE_LOOKUP.get(body.priceId)
    if not stripe_price:
        raise HTTPException(400, "unknown_price")

    success_url = "https://imuvpn.netlify.app/dashboard.html?session_id={CHECKOUT_SESSION_ID}"
    cancel_url = "https://imuvpn.netlify.app/"

    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": stripe_price, "quantity": 1}],
            success_url=success_url,
            cancel_url=cancel_url,
            customer_email=user["email"],
        )
    except Exception as e:
        raise HTTPException(500, f"stripe_error: {e}")

    return {"url": session.url}


# --- Founder / Admin endpoints ---


def require_admin(x_admin_key: Optional[str] = Header(None)) -> None:
    """
    Very simple admin gate using a header.
    In Render, set FOUNDER_API_KEY to a long random string.
    Frontend will send it only from your private founder page.
    """
    expected = os.environ.get("FOUNDER_API_KEY")
    if not expected or x_admin_key != expected:
        raise HTTPException(401, "admin_unauthorized")


@app.get("/admin/overview", response_model=AdminOverview)
def admin_overview(_=Depends(require_admin)):
    total_users = len(USERS)
    active_sessions = len(SESSIONS)
    total_devices = sum(len(v) for v in CONFIGS.values())
    return AdminOverview(
        total_users=total_users,
        active_sessions=active_sessions,
        total_devices=total_devices,
    )

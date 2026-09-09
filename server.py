from dotenv import load_dotenv
load_dotenv()

import os
import re
import ipaddress
import logging
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Annotated

import bcrypt
import jwt
import httpx
from bson import ObjectId
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Request, Response
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr, BeforeValidator, ConfigDict

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

app = FastAPI()
api_router = APIRouter(prefix="/api")

PyObjectId = Annotated[str, BeforeValidator(str)]

from pydantic import AliasChoices


class BaseDocument(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: Optional[PyObjectId] = Field(default=None, validation_alias=AliasChoices("id", "_id"))

    def to_mongo(self) -> dict:
        data = self.model_dump(by_alias=True, exclude={"id"})
        return data

    @classmethod
    def from_mongo(cls, doc: dict):
        doc = dict(doc)
        if "_id" in doc:
            doc["_id"] = str(doc["_id"])
        return cls(**doc)


# ---------------- Vehicles ----------------

class VehicleBase(BaseModel):
    brand: str
    model: str
    year: int
    km: int
    fuel: str
    transmission: str
    power: Optional[int] = None
    price: int
    description: str = ""
    options: str = ""
    images: List[str] = []
    status: str = "disponible"  # disponible | reserve | vendu
    critair: Optional[int] = None  # vignette Crit'Air 1 à 5
    warranty: str = "Garantie 3 mois boîte/moteur"
    history: str = ""  # provenance / historique


class Vehicle(VehicleBase, BaseDocument):
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class VehicleCreate(VehicleBase):
    pass


# ---------------- Leads & Deposits ----------------

from pydantic import field_validator


class RgpdModel(BaseModel):
    rgpd_consent: bool

    @field_validator("rgpd_consent")
    @classmethod
    def consent_required(cls, v):
        if not v:
            raise ValueError("Le consentement RGPD est obligatoire pour traiter votre demande.")
        return v


class LeadCreate(RgpdModel):
    name: str
    phone: str
    email: Optional[EmailStr] = None
    subject: str = "Demande d'information"
    message: str
    vehicle_id: Optional[str] = None
    vehicle_label: Optional[str] = None


class Lead(LeadCreate, BaseDocument):
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DepositCreate(RgpdModel):
    name: str
    phone: str
    email: Optional[EmailStr] = None
    brand: str
    model: str
    year: int
    km: int
    desired_price: Optional[int] = None
    description: str = ""


class Deposit(DepositCreate, BaseDocument):
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------- Auth ----------------

JWT_ALGORITHM = "HS256"


def get_jwt_secret() -> str:
    return os.environ["JWT_SECRET"]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_access_token(user_id: str, email: str) -> str:
    payload = {"sub": user_id, "email": email, "exp": datetime.now(timezone.utc) + timedelta(hours=12), "type": "access"}
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Non authentifié")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expirée")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalide")
    user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
    if not user:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    user["_id"] = str(user["_id"])
    user.pop("password_hash", None)
    return user


class LoginInput(BaseModel):
    email: EmailStr
    password: str


@api_router.post("/auth/login")
async def login(body: LoginInput, request: Request, response: Response):
    email = body.email.lower()
    identifier = f"{request.client.host}:{email}"
    attempt = await db.login_attempts.find_one({"identifier": identifier})
    if attempt and attempt.get("count", 0) >= 5:
        locked_until = attempt.get("locked_until")
        if locked_until and datetime.fromisoformat(locked_until) > datetime.now(timezone.utc):
            raise HTTPException(status_code=429, detail="Trop de tentatives. Réessayez dans 15 minutes.")
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(body.password, user["password_hash"]):
        await db.login_attempts.update_one(
            {"identifier": identifier},
            {"$inc": {"count": 1}, "$set": {"locked_until": (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()}},
            upsert=True,
        )
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
    await db.login_attempts.delete_one({"identifier": identifier})
    token = create_access_token(str(user["_id"]), email)
    response.set_cookie(key="access_token", value=token, httponly=True, secure=True, samesite="none", max_age=43200, path="/")
    return {"id": str(user["_id"]), "email": email, "name": user.get("name", "Admin"), "role": user.get("role", "admin")}


@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    return {"status": "ok"}


@api_router.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return {"id": user["_id"], "email": user["email"], "name": user.get("name", "Admin"), "role": user.get("role", "admin")}


# ---------------- Email (Resend via Emergent proxy) ----------------

EMAIL_BASE_URL = "https://integrations.emergentagent.com"
EMAIL_KEY = os.environ.get("EMERGENT_EMAIL_KEY")
EMAIL_FROM_NAME = os.environ.get("EMAIL_FROM_NAME", "Groupe Huvig")
OWNER_EMAIL = os.environ.get("OWNER_EMAIL")

_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "goo.gl", "rebrand.ly")
_CRED_ASK = ("reply with your password", "reply with the code", "send your password", "cvv",
             "send us your password", "enter your password below", "confirm your card number",
             "your full card number", "seed phrase", "recovery phrase", "verify your card",
             "social security number", "confirm your bank details")
_HOSTISH = re.compile(r"\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)


def _host_ok(host: str) -> bool:
    if not host or "xn--" in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return not any(host == s or host.endswith("." + s) for s in _SHORTENERS)


def _same_site(shown: str, real: str) -> bool:
    return shown == real or real.endswith("." + shown) or shown.endswith("." + real)


class _EmailScan(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.urls, self.anchors = set(), [], []
        self._href, self._text = None, []

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag.lower())
        self.urls += [v for k, v in attrs if k.lower() in ("href", "src") and v]
        if tag.lower() == "a":
            self._href = dict((k.lower(), v) for k, v in attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._text)))
            self._href, self._text = None, []


def _assert_safe_email(subject: str, html: str) -> None:
    scan = _EmailScan()
    scan.feed(html)
    if scan.tags & {"form", "input", "textarea", "select"}:
        raise ValueError("No forms or input fields in email (G2)")
    body = f"{subject}\n{html}".lower()
    for p in _CRED_ASK:
        if p in body:
            raise ValueError(f"Email asks the recipient for credentials: {p!r} (G2)")
    for url in scan.urls:
        low = url.strip().lower()
        if low.startswith(("mailto:", "tel:", "cid:", "#")):
            continue
        if not low.startswith("https://"):
            raise ValueError(f"Email links/assets must be absolute https: {url!r} (G3)")
        host = urlparse(low).hostname or ""
        if not _host_ok(host) or urlparse(low).username is not None:
            raise ValueError(f"Shortened, numeric-host or credential-bearing URL: {url!r} (G3)")
    for href, text in scan.anchors:
        real = urlparse(href.strip().lower()).hostname or ""
        if not real:
            continue
        for m in _HOSTISH.finditer(text):
            if not _same_site(m.group(1).lower(), real):
                raise ValueError(f"Anchor text {m.group(1)!r} != real link host {real!r} (G3)")


async def send_email(*, to: str, subject: str, html: str) -> Optional[str]:
    _assert_safe_email(subject, html)
    payload = {"to": [to], "subject": subject, "html": html, "from_name": EMAIL_FROM_NAME}
    async with httpx.AsyncClient(timeout=30) as http_client:
        resp = await http_client.post(
            f"{EMAIL_BASE_URL}/api/v1/email/send",
            headers={"X-Email-Key": EMAIL_KEY},
            json=payload,
        )
    resp.raise_for_status()
    return resp.json().get("id")


def _email_table(rows: List[tuple], message: str) -> str:
    rows_html = "".join(
        f'<tr><td style="padding:8px 16px;color:#888;font-size:13px;text-transform:uppercase;letter-spacing:1px">{escape(k)}</td>'
        f'<td style="padding:8px 16px;color:#111;font-size:14px"><strong>{escape(str(v))}</strong></td></tr>'
        for k, v in rows if v
    )
    return (
        '<table role="presentation" width="100%" style="font-family:Arial,sans-serif;background:#0A0A0A;padding:32px">'
        '<tr><td>'
        '<p style="color:#FF1E27;font-size:12px;letter-spacing:3px;text-transform:uppercase;margin:0 0 8px">Groupe Huvig</p>'
        '<h1 style="color:#fff;font-size:22px;margin:0 0 24px">Nouvelle demande depuis le site</h1>'
        f'<table role="presentation" width="100%" style="background:#fff;border-radius:8px">{rows_html}'
        f'<tr><td colspan="2" style="padding:16px;color:#333;font-size:14px;line-height:1.6">{escape(message)}</td></tr>'
        "</table>"
        '<p style="color:#666;font-size:11px;margin-top:24px">Envoyé par le site Groupe Huvig. Nous ne demandons jamais de mot de passe par email.</p>'
        "</td></tr></table>"
    )


# ---------------- Public routes ----------------

@api_router.get("/")
async def root():
    return {"message": "Groupe Huvig API"}


@api_router.get("/vehicles", response_model=List[Vehicle])
async def list_vehicles():
    docs = await db.vehicles.find().sort("created_at", -1).to_list(500)
    return [Vehicle.from_mongo(d) for d in docs]


@api_router.get("/vehicles/{vehicle_id}", response_model=Vehicle)
async def get_vehicle(vehicle_id: str):
    doc = await db.vehicles.find_one({"_id": ObjectId(vehicle_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Véhicule introuvable")
    return Vehicle.from_mongo(doc)


@api_router.post("/leads", response_model=Lead)
async def create_lead(body: LeadCreate):
    lead = Lead(**body.model_dump())
    await db.leads.insert_one(lead.to_mongo())
    if OWNER_EMAIL and EMAIL_KEY:
        try:
            rows = [("Nom", lead.name), ("Téléphone", lead.phone), ("Email", lead.email or ""),
                    ("Sujet", lead.subject), ("Véhicule", lead.vehicle_label or "")]
            await send_email(to=OWNER_EMAIL, subject=f"[GHV] {lead.subject} — {lead.name}", html=_email_table(rows, lead.message))
        except Exception as e:
            logger.error(f"Lead email failed: {e}")
    return lead


@api_router.post("/deposits", response_model=Deposit)
async def create_deposit(body: DepositCreate):
    deposit = Deposit(**body.model_dump())
    await db.deposits.insert_one(deposit.to_mongo())
    if OWNER_EMAIL and EMAIL_KEY:
        try:
            rows = [("Nom", deposit.name), ("Téléphone", deposit.phone), ("Email", deposit.email or ""),
                    ("Véhicule", f"{deposit.brand} {deposit.model}"), ("Année", deposit.year),
                    ("Kilométrage", f"{deposit.km} km"),
                    ("Prix souhaité", f"{deposit.desired_price} €" if deposit.desired_price else "")]
            await send_email(to=OWNER_EMAIL, subject=f"[GHV] Proposition de revente — {deposit.brand} {deposit.model}",
                             html=_email_table(rows, deposit.description))
        except Exception as e:
            logger.error(f"Deposit email failed: {e}")
    return deposit


# ---------------- Object storage (photos véhicules) ----------------

import uuid as _uuid
from fastapi import UploadFile, File

STORAGE_BASE = (os.environ.get("INTEGRATION_PROXY_URL") or "").strip() or "https://integrations.emergentagent.com"
STORAGE_URL = STORAGE_BASE.rstrip("/") + "/objstore/api/v1/storage"
STORAGE_APP = "ghv"
_storage_key = None


async def init_storage(force: bool = False) -> str:
    global _storage_key
    if _storage_key and not force:
        return _storage_key
    async with httpx.AsyncClient(timeout=30) as http_client:
        resp = await http_client.post(f"{STORAGE_URL}/init", json={"emergent_key": os.environ.get("EMERGENT_LLM_KEY")})
    resp.raise_for_status()
    _storage_key = resp.json()["storage_key"]
    return _storage_key


async def put_object(path: str, data: bytes, content_type: str) -> dict:
    key = await init_storage()
    async with httpx.AsyncClient(timeout=120) as http_client:
        resp = await http_client.put(f"{STORAGE_URL}/objects/{path}", headers={"X-Storage-Key": key, "Content-Type": content_type}, content=data)
    if resp.status_code == 404:
        key = await init_storage(force=True)
        async with httpx.AsyncClient(timeout=120) as http_client:
            resp = await http_client.put(f"{STORAGE_URL}/objects/{path}", headers={"X-Storage-Key": key, "Content-Type": content_type}, content=data)
    resp.raise_for_status()
    return resp.json()


async def get_object(path: str) -> tuple:
    key = await init_storage()
    async with httpx.AsyncClient(timeout=60) as http_client:
        resp = await http_client.get(f"{STORAGE_URL}/objects/{path}", headers={"X-Storage-Key": key})
    resp.raise_for_status()
    return resp.content, resp.headers.get("Content-Type", "application/octet-stream")


@api_router.post("/uploads")
async def upload_photo(file: UploadFile = File(...), user=Depends(get_current_user)):
    if not (file.content_type or "").startswith("image/"):
        raise HTTPException(status_code=400, detail="Seules les images sont acceptées")
    data = await file.read()
    if len(data) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Image trop lourde (10 Mo max)")
    ext = (file.filename or "photo.jpg").rsplit(".", 1)[-1].lower()
    if ext not in ("jpg", "jpeg", "png", "webp"):
        ext = "jpg"
    path = f"{STORAGE_APP}/uploads/{_uuid.uuid4()}.{ext}"
    result = await put_object(path, data, file.content_type or "image/jpeg")
    await db.files.insert_one({
        "id": str(_uuid.uuid4()),
        "storage_path": result["path"],
        "original_filename": file.filename,
        "content_type": file.content_type or "image/jpeg",
        "size": result.get("size", len(data)),
        "is_deleted": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"url": f"/api/files/{result['path']}", "path": result["path"]}


@api_router.get("/files/{path:path}")
async def serve_file(path: str):
    record = await db.files.find_one({"storage_path": path, "is_deleted": False})
    if not record:
        raise HTTPException(status_code=404, detail="Fichier introuvable")
    data, content_type = await get_object(path)
    return Response(content=data, media_type=record.get("content_type") or content_type)


# ---------------- Admin routes ----------------

@api_router.post("/vehicles", response_model=Vehicle)
async def create_vehicle(body: VehicleCreate, user=Depends(get_current_user)):
    vehicle = Vehicle(**body.model_dump())
    result = await db.vehicles.insert_one(vehicle.to_mongo())
    doc = await db.vehicles.find_one({"_id": result.inserted_id})
    return Vehicle.from_mongo(doc)


@api_router.put("/vehicles/{vehicle_id}", response_model=Vehicle)
async def update_vehicle(vehicle_id: str, body: VehicleCreate, user=Depends(get_current_user)):
    result = await db.vehicles.update_one({"_id": ObjectId(vehicle_id)}, {"$set": body.model_dump()})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Véhicule introuvable")
    doc = await db.vehicles.find_one({"_id": ObjectId(vehicle_id)})
    return Vehicle.from_mongo(doc)


@api_router.delete("/vehicles/{vehicle_id}")
async def delete_vehicle(vehicle_id: str, user=Depends(get_current_user)):
    result = await db.vehicles.delete_one({"_id": ObjectId(vehicle_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Véhicule introuvable")
    return {"status": "deleted"}


@api_router.get("/leads", response_model=List[Lead])
async def list_leads(user=Depends(get_current_user)):
    docs = await db.leads.find().sort("created_at", -1).to_list(500)
    return [Lead.from_mongo(d) for d in docs]


@api_router.get("/deposits", response_model=List[Deposit])
async def list_deposits(user=Depends(get_current_user)):
    docs = await db.deposits.find().sort("created_at", -1).to_list(500)
    return [Deposit.from_mongo(d) for d in docs]


@api_router.get("/admin/stats")
async def admin_stats(user=Depends(get_current_user)):
    total = await db.vehicles.count_documents({})
    available = await db.vehicles.count_documents({"status": "disponible"})
    sold = await db.vehicles.count_documents({"status": "vendu"})
    leads = await db.leads.count_documents({})
    deposits = await db.deposits.count_documents({})
    return {"total_vehicles": total, "available": available, "sold": sold, "leads": leads, "deposits": deposits}


app.include_router(api_router)

_origins = [o for o in [os.environ.get("FRONTEND_URL"), "http://localhost:3000"] if o]
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=_origins or ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------- Startup seeding ----------------

SEED_VEHICLES = [
    {
        "brand": "Porsche", "model": "911 Carrera S (992)", "year": 2021, "km": 28500,
        "fuel": "Essence", "transmission": "Automatique PDK", "power": 450, "price": 119900,
        "description": "Icône absolue de la sportive allemande. Carnet d'entretien complet Porsche, première main, configuration rare. Châssis Sport, échappement sport, intérieur cuir étendu.",
        "options": "Toit ouvrant électrique, Pack Sport Chrono, sièges sport adaptatifs 18 voies, BOSE Surround Sound, PDLS+, caméra de recul",
        "critair": 1, "warranty": "Garantie 12 mois moteur/boîte/pont",
        "history": "Première main, carnet Porsche complet, factures d'entretien disponibles, double des clés, contrôle technique OK.",
        "images": [
            "https://images.unsplash.com/photo-1580446623001-3abf670c5c55?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjAzMzV8MHwxfHNlYXJjaHwxfHxyZWQlMjBzcG9ydHMlMjBjYXJ8ZW58MHx8fHwxNzg4NzI2NjQ1fDA&ixlib=rb-4.1.0&q=85",
            "https://images.unsplash.com/photo-1564435147551-fcd1d3d773f4?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjAzMzV8MHwxfHNlYXJjaHwzfHxyZWQlMjBzcG9ydHMlMjBjYXJ8ZW58MHx8fHwxNzg4NzI2NjQ1fDA&ixlib=rb-4.1.0&q=85",
            "https://images.unsplash.com/photo-1574805094374-5e1ec7a92c8d?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjAzMzV8MHwxfHNlYXJjaHwyfHxyZWQlMjBzcG9ydHMlMjBjYXJ8ZW58MHx8fHwxNzg4NzI2NjQ1fDA&ixlib=rb-4.1.0&q=85",
        ],
        "status": "disponible",
    },
    {
        "brand": "Lamborghini", "model": "Huracán EVO", "year": 2020, "km": 15400,
        "fuel": "Essence", "transmission": "Automatique", "power": 640, "price": 214900,
        "description": "V10 atmosphérique 5.2, configuration Nero Nemesis mate. Véhicule français, jamais sorti sur circuit, suivi Lamborghini intégral.",
        "options": "Peinture mate d'usine, lifting system, intérieur Alcantara, capot moteur transparent, échappement sport",
        "critair": 1, "warranty": "Garantie 12 mois moteur/boîte/pont",
        "history": "Véhicule français, suivi intégral réseau Lamborghini, double des clés, contrôle technique OK.",
        "images": [
            "https://images.unsplash.com/photo-1628519592419-bf288f08cef5?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjA2MjJ8MHwxfHNlYXJjaHwxfHxibGFjayUyMHNwb3J0cyUyMGNhcnxlbnwwfHx8fDE3ODg3MjY2NDV8MA&ixlib=rb-4.1.0&q=85",
            "https://images.unsplash.com/photo-1506610654-064fbba4780c?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjA2MjJ8MHwxfHNlYXJjaHw3fHxibGFjayUyMHNwb3J0cyUyMGNhcnxlbnwwfHx8fDE3ODg3MjY2NDV8MA&ixlib=rb-4.1.0&q=85",
        ],
        "status": "reserve",
    },
    {
        "brand": "BMW", "model": "Série 3 320d (E90)", "year": 2010, "km": 182000,
        "fuel": "Diesel", "transmission": "Manuelle", "power": 184, "price": 10900,
        "description": "La berline routière par excellence. Entretien rigoureux, distribution faite, embrayage récent. Idéale gros rouleur, consommation contenue.",
        "options": "Pack Confort, sièges chauffants, radar de recul, régulateur de vitesse, bluetooth",
        "critair": 3, "warranty": "Garantie 3 mois boîte/moteur",
        "history": "Factures d'entretien disponibles, distribution remplacée, double des clés, contrôle technique OK sans contre-visite.",
        "images": [
            "https://images.unsplash.com/photo-1506610654-064fbba4780c?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjA2MjJ8MHwxfHNlYXJjaHw3fHxibGFjayUyMHNwb3J0cyUyMGNhcnxlbnwwfHx8fDE3ODg3MjY2NDV8MA&ixlib=rb-4.1.0&q=85",
            "https://images.unsplash.com/photo-1706675804583-58600a7e7692?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2NjZ8MHwxfHNlYXJjaHwyfHxwb3JzY2hlJTIwYWxwaW5lJTIwYm13JTIwYXVkaSUyMHNwb3J0cyUyMGNhciUyMGJsYWNrJTIwZGFya3xlbnwwfHx8fDE3ODg3MjY2Mzh8MA&ixlib=rb-4.1.0&q=85",
        ],
        "status": "disponible",
    },
    {
        "brand": "Audi", "model": "A3 Sportback 2.0 TDI S-Line", "year": 2018, "km": 86500,
        "fuel": "Diesel", "transmission": "Automatique S-Tronic", "power": 150, "price": 21900,
        "description": "Compacte premium au look affirmé avec le pack S-Line. Boîte S-Tronic 7 fluide, finition soignée, entretien Audi à jour.",
        "options": "Pack S-Line extérieur/intérieur, Virtual Cockpit, sièges sport, LED Matrix, hayon électrique",
        "critair": 2, "warranty": "Garantie 6 mois moteur/boîte/pont",
        "history": "Carnet Audi à jour, deuxième main, double des clés, contrôle technique OK.",
        "images": [
            "https://images.pexels.com/photos/20131971/pexels-photo-20131971.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
            "https://images.unsplash.com/photo-1706675804583-58600a7e7692?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2NjZ8MHwxfHNlYXJjaHwyfHxwb3JzY2hlJTIwYWxwaW5lJTIwYm13JTIwYXVkaSUyMHNwb3J0cyUyMGNhciUyMGJsYWNrJTIwZGFya3xlbnwwfHx8fDE3ODg3MjY2Mzh8MA&ixlib=rb-4.1.0&q=85",
        ],
        "status": "disponible",
    },
    {
        "brand": "Volkswagen", "model": "Golf 7 GTI Performance", "year": 2017, "km": 74200,
        "fuel": "Essence", "transmission": "Automatique DSG", "power": 245, "price": 24900,
        "description": "La référence des compactes sportives. Châssis joueur, DSG6 rapide, entretien suivi. Un daily parfait qui ne se démode pas.",
        "options": "Pack Performance (freins, autobloquant), Discover Pro, ACC, sièges tartan, mode de conduite",
        "critair": 1, "warranty": "Garantie 6 mois moteur/boîte/pont",
        "history": "Factures d'entretien disponibles, révision DSG effectuée, double des clés, contrôle technique OK.",
        "images": [
            "https://images.unsplash.com/photo-1574805094374-5e1ec7a92c8d?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjAzMzV8MHwxfHNlYXJjaHwyfHxyZWQlMjBzcG9ydHMlMjBjYXJ8ZW58MHx8fHwxNzg4NzI2NjQ1fDA&ixlib=rb-4.1.0&q=85",
            "https://images.unsplash.com/photo-1564435147551-fcd1d3d773f4?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjAzMzV8MHwxfHNlYXJjaHwzfHxyZWQlMjBzcG9ydHMlMjBjYXJ8ZW58MHx8fHwxNzg4NzI2NjQ1fDA&ixlib=rb-4.1.0&q=85",
        ],
        "status": "vendu",
    },
    {
        "brand": "Seat", "model": "Leon FR 1.5 TSI", "year": 2020, "km": 56800,
        "fuel": "Essence", "transmission": "Manuelle", "power": 150, "price": 18900,
        "description": "Finition FR dynamique, moteur 1.5 TSI souple et économe. Compacte familiale au tempérament sportif, entretien à jour.",
        "options": "Pack FR, Full Link, caméra de recul, jantes 18 pouces, climatisation bi-zone, feux full LED",
        "critair": 1, "warranty": "Garantie 6 mois moteur/boîte/pont",
        "history": "Première main, factures d'entretien disponibles, double des clés, contrôle technique OK.",
        "images": [
            "https://images.pexels.com/photos/38304542/pexels-photo-38304542.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
            "https://images.unsplash.com/photo-1564435147551-fcd1d3d773f4?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjAzMzV8MHwxfHNlYXJjaHwzfHxyZWQlMjBzcG9ydHMlMjBjYXJ8ZW58MHx8fHwxNzg4NzI2NjQ1fDA&ixlib=rb-4.1.0&q=85",
        ],
        "status": "disponible",
    },
]


@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.login_attempts.create_index("identifier")

    admin_email = os.environ.get("ADMIN_EMAIL", "admin@groupehuvig.fr").lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    existing = await db.users.find_one({"email": admin_email})
    if existing is None:
        await db.users.insert_one({
            "email": admin_email,
            "password_hash": hash_password(admin_password),
            "name": "Admin GHV",
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        logger.info(f"Admin seeded: {admin_email}")
    elif not verify_password(admin_password, existing["password_hash"]):
        await db.users.update_one({"email": admin_email}, {"$set": {"password_hash": hash_password(admin_password)}})
        logger.info("Admin password updated from env")

    if await db.vehicles.count_documents({}) == 0:
        for v in SEED_VEHICLES:
            await db.vehicles.insert_one(Vehicle(**v).to_mongo())
        logger.info(f"Seeded {len(SEED_VEHICLES)} vehicles")


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

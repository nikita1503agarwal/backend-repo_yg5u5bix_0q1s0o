import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
import jwt
from jwt import exceptions as jwt_exc
from passlib.context import CryptContext
import requests
from bson import ObjectId

from database import db
from schemas import (
    User as UserSchema,
    Admin as AdminSchema,
    TeamMember as TeamMemberSchema,
    BlogPost as BlogPostSchema,
    Service as ServiceSchema,
    Session as SessionSchema,
)

# App and CORS
app = FastAPI(title="CodeGummies API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security settings
JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret_change_me")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

# Collections
COLL_USERS = "user"
COLL_ADMINS = "admin"
COLL_TEAM = "teammember"
COLL_POSTS = "blogpost"
COLL_SERVICES = "service"
COLL_SESSIONS = "session"

# Helpers
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class SignupPayload(BaseModel):
    name: str
    email: EmailStr
    password: str

class GoogleLoginPayload(BaseModel):
    id_token: str

class UpdateProfilePayload(BaseModel):
    name: Optional[str] = None
    avatar_url: Optional[str] = None

# Rate limiting (simple in-memory per-IP, for auth endpoints)
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 10
_rate_counters = {}

def rate_limit(request: Request):
    ip = request.client.host if request.client else "unknown"
    now = datetime.now(timezone.utc).timestamp()
    window = int(now // RATE_LIMIT_WINDOW)
    key = f"{ip}:{window}"
    count = _rate_counters.get(key, 0)
    if count >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")
    _rate_counters[key] = count + 1

# JWT utilities

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

async def get_current_user(request: Request):
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = auth.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        role: str = payload.get("role")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt_exc.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    coll = COLL_USERS if role != "admin" else COLL_ADMINS
    doc = db[coll].find_one({"_id": ObjectId(user_id)}) if user_id and db is not None else None
    if not doc:
        raise HTTPException(status_code=401, detail="User not found")
    doc["id"] = str(doc.pop("_id"))
    return {"role": role or "user", **doc}

async def require_admin(user = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# Admin bootstrap (optional via env)
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if db is not None and ADMIN_EMAIL and ADMIN_PASSWORD:
    if db[COLL_ADMINS].count_documents({"email": ADMIN_EMAIL}) == 0:
        db[COLL_ADMINS].insert_one({
            "name": "Admin",
            "email": ADMIN_EMAIL,
            "password_hash": pwd_context.hash(ADMIN_PASSWORD),
            "role": "admin",
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        })

@app.get("/")
def read_root():
    return {"message": "CodeGummies API running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": os.getenv("DATABASE_NAME") or "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"⚠️ Error: {str(e)[:80]}"
    return response

# Auth routes
@app.post("/auth/signup", response_model=Token)
async def signup(payload: SignupPayload, request: Request):
    rate_limit(request)
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    if db[COLL_USERS].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    password_hash = pwd_context.hash(payload.password)
    now = datetime.now(timezone.utc)
    user_doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": password_hash,
        "provider": "local",
        "email_verified": False,
        "role": "user",
        "created_at": now,
        "updated_at": now,
    }
    inserted_id = db[COLL_USERS].insert_one(user_doc).inserted_id
    token = create_access_token({"sub": str(inserted_id), "role": "user"})
    # session record
    session = {
        "user_id": str(inserted_id),
        "role": "user",
        "user_agent": request.headers.get("user-agent"),
        "ip": request.client.host if request.client else None,
        "expires_at": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "created_at": now,
        "updated_at": now,
    }
    db[COLL_SESSIONS].insert_one(session)
    return Token(access_token=token)

@app.post("/auth/login", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends(), request: Request = None):
    rate_limit(request)
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    doc = db[COLL_USERS].find_one({"email": form.username})
    if not doc or not doc.get("password_hash") or not pwd_context.verify(form.password, doc["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": str(doc["_id"]), "role": "user"})
    now = datetime.now(timezone.utc)
    db[COLL_SESSIONS].insert_one({
        "user_id": str(doc["_id"]),
        "role": "user",
        "user_agent": request.headers.get("user-agent") if request else None,
        "ip": request.client.host if request and request.client else None,
        "expires_at": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "created_at": now,
        "updated_at": now,
    })
    return Token(access_token=token)

@app.post("/auth/google", response_model=Token)
async def google_login(payload: GoogleLoginPayload, request: Request):
    rate_limit(request)
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    email = None
    name = None
    try:
        resp = requests.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"id_token": payload.id_token},
            timeout=5,
        )
        data = resp.json()
        if resp.status_code == 200 and (not GOOGLE_CLIENT_ID or data.get("aud") == GOOGLE_CLIENT_ID):
            email = data.get("email")
            name = data.get("name") or (email.split("@")[0] if email else None)
    except Exception:
        pass
    if not email:
        raise HTTPException(status_code=401, detail="Invalid Google token")

    doc = db[COLL_USERS].find_one({"email": email})
    if not doc:
        now = datetime.now(timezone.utc)
        user_doc = {
            "name": name or "User",
            "email": email,
            "provider": "google",
            "email_verified": True,
            "role": "user",
            "created_at": now,
            "updated_at": now,
        }
        inserted_id = db[COLL_USERS].insert_one(user_doc).inserted_id
        user_id = str(inserted_id)
    else:
        user_id = str(doc["_id"])
    token = create_access_token({"sub": user_id, "role": "user"})
    return Token(access_token=token)

@app.post("/auth/admin/login", response_model=Token)
async def admin_login(form: OAuth2PasswordRequestForm = Depends(), request: Request = None):
    rate_limit(request)
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    doc = db[COLL_ADMINS].find_one({"email": form.username})
    if not doc or not pwd_context.verify(form.password, doc["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": str(doc["_id"]), "role": "admin"})
    return Token(access_token=token)

# User profile
@app.get("/me")
async def get_me(user = Depends(get_current_user)):
    return {k: v for k, v in user.items() if k != "password_hash"}

@app.put("/me")
async def update_me(payload: UpdateProfilePayload, user = Depends(get_current_user)):
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not updates:
        return user
    updates.update({"updated_at": datetime.now(timezone.utc)})
    coll = COLL_USERS if user.get("role") != "admin" else COLL_ADMINS
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    db[coll].update_one({"_id": ObjectId(user["id"])}, {"$set": updates})
    user.update(updates)
    return user

# Public data endpoints
@app.get("/services", response_model=List[ServiceSchema])
async def list_services():
    if db is None:
        return []
    items = list(db[COLL_SERVICES].find({"active": True}))
    for it in items:
        it.pop("_id", None)
    return items

@app.get("/blog", response_model=List[BlogPostSchema])
async def list_blog_posts():
    if db is None:
        return []
    items = list(db[COLL_POSTS].find({"published": True}))
    for it in items:
        it.pop("_id", None)
    return items

@app.get("/blog/{slug}")
async def get_blog_post(slug: str):
    if db is None:
        raise HTTPException(status_code=404, detail="Post not found")
    doc = db[COLL_POSTS].find_one({"slug": slug, "published": True})
    if not doc:
        raise HTTPException(status_code=404, detail="Post not found")
    doc["id"] = str(doc.pop("_id"))
    return doc

@app.get("/team")
async def get_team():
    if db is None:
        return []
    items = list(db[COLL_TEAM].find({"active": True}))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items

# Admin CRUD
@app.post("/admin/services")
async def create_service(payload: ServiceSchema, admin = Depends(require_admin)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    doc = payload.model_dump()
    now = datetime.now(timezone.utc)
    doc.update({"created_at": now, "updated_at": now})
    _id = db[COLL_SERVICES].insert_one(doc).inserted_id
    return {"id": str(_id)}

@app.put("/admin/services/{slug}")
async def update_service(slug: str, payload: ServiceSchema, admin = Depends(require_admin)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    doc = payload.model_dump()
    doc.update({"updated_at": datetime.now(timezone.utc)})
    res = db[COLL_SERVICES].update_one({"slug": slug}, {"$set": doc})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Service not found")
    return {"ok": True}

@app.delete("/admin/services/{slug}")
async def delete_service(slug: str, admin = Depends(require_admin)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    db[COLL_SERVICES].delete_one({"slug": slug})
    return {"ok": True}

@app.post("/admin/blog")
async def create_post(payload: BlogPostSchema, admin = Depends(require_admin)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    doc = payload.model_dump()
    now = datetime.now(timezone.utc)
    doc.update({"created_at": now, "updated_at": now})
    _id = db[COLL_POSTS].insert_one(doc).inserted_id
    return {"id": str(_id)}

@app.put("/admin/blog/{slug}")
async def update_post(slug: str, payload: BlogPostSchema, admin = Depends(require_admin)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    doc = payload.model_dump()
    doc.update({"updated_at": datetime.now(timezone.utc)})
    res = db[COLL_POSTS].update_one({"slug": slug}, {"$set": doc})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Post not found")
    return {"ok": True}

@app.delete("/admin/blog/{slug}")
async def delete_post(slug: str, admin = Depends(require_admin)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    db[COLL_POSTS].delete_one({"slug": slug})
    return {"ok": True}

@app.post("/admin/team")
async def create_team_member(payload: TeamMemberSchema, admin = Depends(require_admin)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    doc = payload.model_dump()
    now = datetime.now(timezone.utc)
    doc.update({"created_at": now, "updated_at": now})
    _id = db[COLL_TEAM].insert_one(doc).inserted_id
    return {"id": str(_id)}

@app.put("/admin/team/{name}")
async def update_team_member(name: str, payload: TeamMemberSchema, admin = Depends(require_admin)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    doc = payload.model_dump()
    doc.update({"updated_at": datetime.now(timezone.utc)})
    res = db[COLL_TEAM].update_one({"name": name}, {"$set": doc})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Team member not found")
    return {"ok": True}

@app.delete("/admin/team/{name}")
async def delete_team_member(name: str, admin = Depends(require_admin)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    db[COLL_TEAM].delete_one({"name": name})
    return {"ok": True}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

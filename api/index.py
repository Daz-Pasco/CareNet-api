from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from supabase import create_client, Client
import os

# Initialize Supabase
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")

if url and key:
    supabase: Client = create_client(url, key)
else:
    supabase = None


# ===== MODELS =====

class CompleteProfileRequest(BaseModel):
    full_name: str
    role: str
    phone: Optional[str] = None


class UserProfile(BaseModel):
    id: str
    email: str
    full_name: str
    avatar_url: Optional[str]
    phone: Optional[str]
    role: str


# ===== HELPERS =====

def get_user_profile(user_id: str) -> Optional[dict]:
    if not supabase:
        return None
    result = supabase.table("users").select("*").eq("id", user_id).execute()
    if result.data and len(result.data) > 0:
        return result.data[0]
    return None


async def get_current_user(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    token = authorization.replace("Bearer ", "")
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    try:
        user_response = supabase.auth.get_user(token)
        user = user_response.user
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        profile = get_user_profile(user.id)
        if not profile:
            raise HTTPException(status_code=403, detail="Profile not completed")
        return profile
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


# ===== APP =====

app = FastAPI(title="CareNet API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"message": "Hello from CareNet API"}


@app.get("/health")
def health_check():
    return {"status": "ok", "supabase_connected": supabase is not None}


# ===== AUTH PROFILE ENDPOINTS =====
# OAuth is now handled natively in the mobile app via Supabase SDK
# These endpoints remain for profile management after authentication

@app.post("/auth/complete-profile", response_model=UserProfile)
def complete_profile(profile_data: CompleteProfileRequest, authorization: str = Header(...)):
    """
    Complete user profile after first login.
    Called from the mobile app after user authenticates with Google.
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    valid_roles = ['elderly', 'family_supervisor', 'professional']
    if profile_data.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    token = authorization.replace("Bearer ", "")
    try:
        user_response = supabase.auth.get_user(token)
        user = user_response.user
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        existing = get_user_profile(user.id)
        if existing:
            raise HTTPException(status_code=400, detail="Profile already exists")
        
        # Get metadata from Google OAuth
        metadata = user.user_metadata or {}
        new_user = {
            "id": user.id,
            "email": user.email,
            "full_name": profile_data.full_name,
            "avatar_url": metadata.get("avatar_url") or metadata.get("picture"),
            "phone": profile_data.phone,
            "role": profile_data.role
        }
        result = supabase.table("users").insert(new_user).execute()
        if not result.data:
            raise HTTPException(status_code=500, detail="Failed to create profile")
        created = result.data[0]
        return UserProfile(
            id=created["id"],
            email=created["email"],
            full_name=created["full_name"],
            avatar_url=created.get("avatar_url"),
            phone=created.get("phone"),
            role=created["role"]
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/auth/me", response_model=UserProfile)
def get_me(current_user=Depends(get_current_user)):
    """Get current authenticated user's profile."""
    return UserProfile(
        id=current_user["id"],
        email=current_user["email"],
        full_name=current_user["full_name"],
        avatar_url=current_user.get("avatar_url"),
        phone=current_user.get("phone"),
        role=current_user["role"]
    )

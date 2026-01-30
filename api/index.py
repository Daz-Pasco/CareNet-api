from fastapi import FastAPI, HTTPException, Header
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


def get_user_client(token: str) -> Client:
    """Create a Supabase client authenticated with the user's token for RLS."""
    if not url or not key:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    client = create_client(url, key)
    # Set the user's access token for RLS context
    client.auth.set_session(token, token)
    return client


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

@app.post("/auth/complete-profile", response_model=UserProfile)
def complete_profile(profile_data: CompleteProfileRequest, authorization: str = Header(...)):
    """
    Complete user profile after first login.
    Uses user's token for RLS context.
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    valid_roles = ['elderly', 'family_supervisor', 'professional']
    if profile_data.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {valid_roles}")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    
    try:
        # Verify user token
        user_response = supabase.auth.get_user(token)
        user = user_response.user
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Create user-authenticated client for RLS
        user_client = get_user_client(token)
        
        # Check if profile already exists
        existing = user_client.table("users").select("*").eq("id", user.id).execute()
        if existing.data and len(existing.data) > 0:
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
        
        # Insert with user's RLS context
        result = user_client.table("users").insert(new_user).execute()
        
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
def get_me(authorization: str = Header(...)):
    """Get current authenticated user's profile."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    
    try:
        user_response = supabase.auth.get_user(token)
        user = user_response.user
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Create user-authenticated client for RLS
        user_client = get_user_client(token)
        
        result = user_client.table("users").select("*").eq("id", user.id).execute()
        if not result.data or len(result.data) == 0:
            raise HTTPException(status_code=404, detail="Profile not found")
        
        profile = result.data[0]
        return UserProfile(
            id=profile["id"],
            email=profile["email"],
            full_name=profile["full_name"],
            avatar_url=profile.get("avatar_url"),
            phone=profile.get("phone"),
            role=profile["role"]
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

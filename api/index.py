from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from supabase import create_client, Client
import os

# Initialize Supabase clients
url = os.environ.get("SUPABASE_URL")
anon_key = os.environ.get("SUPABASE_KEY")  # For auth verification
service_role_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")  # For DB operations

# Client for auth verification (anon key)
if url and anon_key:
    supabase: Client = create_client(url, anon_key)
else:
    supabase = None

# Admin client for DB operations (service role key - bypasses RLS)
if url and service_role_key:
    supabase_admin: Client = create_client(url, service_role_key)
elif url and anon_key:
    # Fallback to anon key if service role not set
    supabase_admin = supabase
else:
    supabase_admin = None


# ===== MODELS =====

class CompleteProfileRequest(BaseModel):
    full_name: str
    role: str
    phone: Optional[str] = None


class CompleteProfessionalRequest(BaseModel):
    """Professional registration - creates user + professional_profiles"""
    full_name: str
    phone: str
    professional_email: str
    specialization: str
    workplace: Optional[str] = None


class CompleteCaregiverRequest(BaseModel):
    """Caregiver registration - creates user + elderly_profiles + medical_info"""
    full_name: str
    patient_phone: str
    caregiver_phone: str
    date_of_birth: str  # DD/MM/YYYY format
    gender: str  # male, female, other
    height_cm: int
    weight_kg: float
    address: str
    allergies: List[str] = []
    conditions: List[str] = []
    medications: List[str] = []


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
    return {
        "status": "ok", 
        "supabase_connected": supabase is not None,
        "service_role_enabled": supabase_admin is not supabase
    }


# ===== AUTH PROFILE ENDPOINTS =====

@app.post("/auth/complete-profile", response_model=UserProfile)
def complete_profile(profile_data: CompleteProfileRequest, authorization: str = Header(...)):
    """
    Complete user profile after first login.
    Uses anon key to verify user token, then service_role key to insert (bypasses RLS).
    """
    if not supabase or not supabase_admin:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    valid_roles = ['elderly', 'family_supervisor', 'professional']
    if profile_data.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {valid_roles}")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    
    try:
        # 1. Verify user token with anon key
        user_response = supabase.auth.get_user(token)
        user = user_response.user
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # 2. Check if profile already exists (using admin to bypass RLS)
        existing = supabase_admin.table("users").select("*").eq("id", user.id).execute()
        if existing.data and len(existing.data) > 0:
            raise HTTPException(status_code=400, detail="Profile already exists")
        
        # 3. Prepare new user data
        metadata = user.user_metadata or {}
        new_user = {
            "id": user.id,
            "email": user.email,
            "full_name": profile_data.full_name,
            "avatar_url": metadata.get("avatar_url") or metadata.get("picture"),
            "phone": profile_data.phone,
            "role": profile_data.role
        }
        
        # 4. Insert using service_role key (bypasses RLS)
        result = supabase_admin.table("users").insert(new_user).execute()
        
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
    if not supabase or not supabase_admin:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    
    try:
        # Verify user token
        user_response = supabase.auth.get_user(token)
        user = user_response.user
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Get profile using admin client
        result = supabase_admin.table("users").select("*").eq("id", user.id).execute()
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


@app.post("/auth/complete-professional", response_model=UserProfile)
def complete_professional(data: CompleteProfessionalRequest, authorization: str = Header(...)):
    """
    Complete professional registration.
    Creates user in 'users' table + professional profile in 'professional_profiles' table.
    """
    if not supabase or not supabase_admin:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    
    try:
        # 1. Verify user token
        user_response = supabase.auth.get_user(token)
        user = user_response.user
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # 2. Check if profile already exists
        existing = supabase_admin.table("users").select("*").eq("id", user.id).execute()
        if existing.data and len(existing.data) > 0:
            raise HTTPException(status_code=400, detail="Profile already exists")
        
        # 3. Insert user
        metadata = user.user_metadata or {}
        new_user = {
            "id": user.id,
            "email": user.email,
            "full_name": data.full_name,
            "avatar_url": metadata.get("avatar_url") or metadata.get("picture"),
            "phone": data.phone,
            "role": "professional"
        }
        user_result = supabase_admin.table("users").insert(new_user).execute()
        if not user_result.data:
            raise HTTPException(status_code=500, detail="Failed to create user profile")
        
        # 4. Insert professional profile
        professional_profile = {
            "user_id": user.id,
            "professional_email": data.professional_email,
            "specialization": data.specialization,
            "workplace": data.workplace or None
        }
        prof_result = supabase_admin.table("professional_profiles").insert(professional_profile).execute()
        if not prof_result.data:
            raise HTTPException(status_code=500, detail="Failed to create professional profile")
        
        created = user_result.data[0]
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


@app.post("/auth/complete-caregiver", response_model=UserProfile)
def complete_caregiver(data: CompleteCaregiverRequest, authorization: str = Header(...)):
    """
    Complete caregiver registration.
    Creates user in 'users' table + elderly profile in 'elderly_profiles' table + medical info.
    """
    if not supabase or not supabase_admin:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    
    try:
        # 1. Verify user token
        user_response = supabase.auth.get_user(token)
        user = user_response.user
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # 2. Check if profile already exists
        existing = supabase_admin.table("users").select("*").eq("id", user.id).execute()
        if existing.data and len(existing.data) > 0:
            raise HTTPException(status_code=400, detail="Profile already exists")
        
        # 3. Convert date from DD/MM/YYYY to YYYY-MM-DD
        date_parts = data.date_of_birth.split("/")
        if len(date_parts) == 3:
            date_of_birth_iso = f"{date_parts[2]}-{date_parts[1]}-{date_parts[0]}"
        else:
            date_of_birth_iso = data.date_of_birth  # Fallback, assume already ISO
        
        # 4. Insert user
        metadata = user.user_metadata or {}
        new_user = {
            "id": user.id,
            "email": user.email,
            "full_name": data.full_name,
            "avatar_url": metadata.get("avatar_url") or metadata.get("picture"),
            "phone": data.patient_phone,
            "role": "family_supervisor",
            "emergency_contact": data.caregiver_phone
        }
        user_result = supabase_admin.table("users").insert(new_user).execute()
        if not user_result.data:
            raise HTTPException(status_code=500, detail="Failed to create user profile")
        
        # 5. Insert elderly profile
        elderly_profile = {
            "user_id": user.id,
            "date_of_birth": date_of_birth_iso,
            "gender": data.gender,
            "height_cm": data.height_cm,
            "weight_kg": data.weight_kg,
            "home_address": data.address
        }
        elderly_result = supabase_admin.table("elderly_profiles").insert(elderly_profile).execute()
        if not elderly_result.data:
            raise HTTPException(status_code=500, detail="Failed to create elderly profile")
        
        # 6. Insert medical info (allergies, conditions, medications)
        for allergy in data.allergies:
            supabase_admin.table("medical_info").insert({
                "elderly_id": user.id,
                "info_type": "allergy",
                "name": allergy,
                "added_by": user.id
            }).execute()
        
        for condition in data.conditions:
            supabase_admin.table("medical_info").insert({
                "elderly_id": user.id,
                "info_type": "condition",
                "name": condition,
                "added_by": user.id
            }).execute()
        
        for medication in data.medications:
            supabase_admin.table("medical_info").insert({
                "elderly_id": user.id,
                "info_type": "medication",
                "name": medication,
                "added_by": user.id
            }).execute()
        
        created = user_result.data[0]
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


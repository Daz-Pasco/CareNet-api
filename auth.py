from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel
from typing import Optional
from database import supabase

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ===== MODELS =====

class AuthResponse(BaseModel):
    url: str


class TokenRequest(BaseModel):
    access_token: str


class GoogleUserData(BaseModel):
    """Data retrieved from Google OAuth"""
    id: str
    email: str
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None


class LoginResponse(BaseModel):
    """Response after verifying token"""
    user: GoogleUserData
    needs_onboarding: bool
    profile: Optional[dict] = None


class CompleteProfileRequest(BaseModel):
    """Data needed to complete onboarding"""
    full_name: str
    role: str  # 'elderly', 'family_supervisor', 'professional'
    phone: Optional[str] = None


class UserProfile(BaseModel):
    id: str
    email: str
    full_name: str
    avatar_url: Optional[str]
    phone: Optional[str]
    role: str


# ===== HELPERS =====

def extract_google_metadata(user) -> GoogleUserData:
    """Extract user data from Supabase auth user (includes Google metadata)"""
    metadata = user.user_metadata or {}
    
    return GoogleUserData(
        id=user.id,
        email=user.email,
        full_name=metadata.get("full_name") or metadata.get("name"),
        avatar_url=metadata.get("avatar_url") or metadata.get("picture")
    )


def get_user_profile(user_id: str) -> Optional[dict]:
    """Check if user has completed profile in users table"""
    if not supabase:
        return None
    
    result = supabase.table("users").select("*").eq("id", user_id).execute()
    
    if result.data and len(result.data) > 0:
        return result.data[0]
    return None


# ===== ENDPOINTS =====

@router.get("/login/google", response_model=AuthResponse)
def login_with_google(redirect_to: Optional[str] = None):
    """
    Returns the Google OAuth URL.
    The frontend should redirect the user to this URL.
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    callback_url = redirect_to or "http://localhost:8000/auth/callback"
    
    response = supabase.auth.sign_in_with_oauth({
        "provider": "google",
        "options": {
            "redirect_to": callback_url
        }
    })
    
    return {"url": response.url}


@router.get("/callback")
def auth_callback(code: Optional[str] = None, error: Optional[str] = None):
    """
    OAuth callback endpoint.
    Supabase redirects here after Google authentication.
    """
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    if not code:
        raise HTTPException(status_code=400, detail="No authorization code provided")
    
    return {
        "message": "Authentication successful",
        "code": code,
        "note": "Exchange this code on the frontend using supabase.auth.exchangeCodeForSession()"
    }


@router.post("/verify", response_model=LoginResponse)
def verify_token(token_request: TokenRequest):
    """
    Verify an access token and return user info.
    Returns Google metadata + whether user needs onboarding.
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    try:
        user_response = supabase.auth.get_user(token_request.access_token)
        user = user_response.user
        
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Extract Google metadata
        google_data = extract_google_metadata(user)
        
        # Check if user has completed profile
        profile = get_user_profile(user.id)
        
        return LoginResponse(
            user=google_data,
            needs_onboarding=profile is None,
            profile=profile
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.post("/complete-profile", response_model=UserProfile)
def complete_profile(
    profile_data: CompleteProfileRequest,
    authorization: str = Header(...)
):
    """
    Complete user onboarding by creating profile in users table.
    Called after first Google login.
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    # Validate role
    valid_roles = ['elderly', 'family_supervisor', 'professional']
    if profile_data.role not in valid_roles:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid role. Must be one of: {valid_roles}"
        )
    
    # Get current user from token
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    
    try:
        user_response = supabase.auth.get_user(token)
        user = user_response.user
        
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Check if profile already exists
        existing = get_user_profile(user.id)
        if existing:
            raise HTTPException(status_code=400, detail="Profile already exists")
        
        # Get Google metadata for avatar
        google_data = extract_google_metadata(user)
        
        # Create user record
        new_user = {
            "id": user.id,
            "email": user.email,
            "full_name": profile_data.full_name,
            "avatar_url": google_data.avatar_url,
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


# ===== PROTECTED ROUTE DEPENDENCY =====

async def get_current_user(authorization: str = Header(...)):
    """
    Dependency to get the current authenticated user.
    Use this to protect routes.
    """
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
        
        # Get full profile from users table
        profile = get_user_profile(user.id)
        
        if not profile:
            raise HTTPException(
                status_code=403, 
                detail="Profile not completed. Call /auth/complete-profile first."
            )
        
        return profile
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.get("/me", response_model=UserProfile)
def get_me(current_user = Depends(get_current_user)):
    """
    Get the current authenticated user's profile.
    Requires completed onboarding.
    """
    return UserProfile(
        id=current_user["id"],
        email=current_user["email"],
        full_name=current_user["full_name"],
        avatar_url=current_user.get("avatar_url"),
        phone=current_user.get("phone"),
        role=current_user["role"]
    )

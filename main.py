from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import supabase
from auth import router as auth_router

app = FastAPI(title="CareNet API", version="1.0.0")

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)


@app.get("/")
def read_root():
    return {"message": "Hello from CareNet API"}


@app.get("/health")
def health_check():
    return {"status": "ok", "supabase_connected": supabase is not None}


# Vercel handler
handler = app


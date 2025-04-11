from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os

from .routers import threat_intelligence, user_management, ml_models

app = FastAPI(
    title="Cybersecurity Threat Intelligence Platform",
    description="AI-driven threat intelligence and analysis system",
    version="0.1.0"
)

# CORS middleware to allow frontend interactions
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers for different modules
app.include_router(threat_intelligence.router, prefix="/api/threats")
app.include_router(user_management.router, prefix="/api/users")
app.include_router(ml_models.router, prefix="/api/ml")

@app.on_event("startup")
async def startup_event():
    """
    Perform startup checks and initializations
    """
    # Check critical environment variables
    required_envs = [
        'VIRUSTOTAL_API_KEY', 
        'ALIENVAULT_API_KEY', 
        'MONGODB_CONNECTION_STRING'
    ]
    for env in required_envs:
        if not os.getenv(env):
            print(f"Warning: {env} environment variable is not set")

@app.get("/health")
async def health_check():
    """
    Simple health check endpoint
    """
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
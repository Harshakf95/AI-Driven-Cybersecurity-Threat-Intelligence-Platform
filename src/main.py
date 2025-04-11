from fastapi import FastAPI
from src.api import threat_stats

app = FastAPI()

# Include routers
app.include_router(threat_stats.router)

@app.get("/")
async def root():
    return {"message": "Cybersecurity Threat Intelligence Platform"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
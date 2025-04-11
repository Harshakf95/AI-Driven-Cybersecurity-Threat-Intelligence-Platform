from fastapi import APIRouter
from pymongo import MongoClient
from typing import Dict
from datetime import datetime, timedelta

router = APIRouter()

# MongoDB Connection
client = MongoClient('mongodb://localhost:27017/')
db = client['cybersecurity_db']
threats_collection = db['threat_indicators']

@router.get("/api/threat-stats")
async def get_threat_statistics() -> Dict[str, int]:
    """
    Fetch threat statistics from MongoDB
    """
    try:
        total_threats = threats_collection.count_documents({})
        high_risk_threats = threats_collection.count_documents({"risk_level": "high"})
        active_threats = threats_collection.count_documents({
            "status": "active", 
            "timestamp": {"$gte": datetime.now() - timedelta(days=1)}
        })
        
        return {
            "total_threats": total_threats,
            "high_risk_threats": high_risk_threats,
            "active_threats": active_threats
        }
    except Exception as e:
        # Log the error
        print(f"Error fetching threat stats: {e}")
        return {
            "total_threats": 0,
            "high_risk_threats": 0,
            "active_threats": 0
        }
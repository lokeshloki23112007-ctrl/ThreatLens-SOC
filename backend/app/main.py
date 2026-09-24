from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes.analyze import router as analyze_router


app = FastAPI(
    title="ThreatLens API",
    description="Phishing Intelligence & SOC Prioritization Backend",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router)


@app.get("/")
def root():
    return {
        "application": "ThreatLens",
        "status": "online",
        "message": "ThreatLens backend is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }
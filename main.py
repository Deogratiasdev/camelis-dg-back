from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes.auth_routes import auth_router
from routes.security_routes import security_router
from middleware.rate_limit_middleware import RateLimitMiddleware
import logging
from datetime import datetime
from dotenv import load_dotenv
import os

# Charger les variables d'environnement depuis .env
load_dotenv()

app = FastAPI(title="API Authentification Simple")

# Configuration logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ajouter le middleware de rate limiting
app.add_middleware(RateLimitMiddleware)

# Inclure les routes
app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(security_router, prefix="/security", tags=["security"])

@app.get("/")
async def root():
    return {"message": "API d'authentification simple"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from json_storage import storage
from services.ai_security_service import ai_security_service
import logging
import hashlib
from datetime import datetime

logger = logging.getLogger(__name__)
security_router = APIRouter()
security = HTTPBearer()

def generate_device_fingerprint(request: Request) -> str:
    """Génère un fingerprint de device basique"""
    user_agent = request.headers.get("user-agent", "")
    ip = request.client.host if request.client else "unknown"
    return hashlib.md5(f"{ip}_{user_agent}".encode()).hexdigest()[:16]

class SecurityAnalysisRequest(BaseModel):
    analysis_type: str  # "anomalies", "threats", "recommendations"
    time_range: str = "24h"  # "24h", "7d", "30d"
    filters: dict = {}

class BehavioralAnalysisRequest(BaseModel):
    user_id: str
    request_data: dict = {}

# === ROUTES D'ANALYSE IA ===

@security_router.post("/ai/analyze-anomalies")
async def analyze_anomalies(
    request: SecurityAnalysisRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    http_request: Request = None
):
    """Analyse les anomalies avec l'IA (personnalisée pour l'utilisateur)"""
    try:
        token = credentials.credentials
        user = storage.get_user_by_token(token)
        
        if not user:
            raise HTTPException(status_code=401, detail="Token invalide")
        
        # Récupérer les logs selon la période
        logs = storage.get_all_logs(limit=1000)  # Tous les logs récents
        
        # Filtrer par time_range
        if request.time_range == "24h":
            from datetime import datetime, timedelta
            cutoff = datetime.now() - timedelta(hours=24)
            logs = [log for log in logs if datetime.fromisoformat(log['timestamp']) > cutoff]
        elif request.time_range == "7d":
            from datetime import datetime, timedelta
            cutoff = datetime.now() - timedelta(days=7)
            logs = [log for log in logs if datetime.fromisoformat(log['timestamp']) > cutoff]
        
        # Filtrer les logs pour cet utilisateur uniquement
        user_logs = [log for log in logs if log.get('user_id') == user['id']]
        
        # Préparer les informations utilisateur pour l'IA
        user_info = {
            "first_name": user.get('first_name', ''),
            "last_name": user.get('last_name', ''),
            "email": user.get('email', ''),
            "is_verified": user.get('is_verified', False),
            "created_at": user.get('created_at', '')
        }
        
        # Analyser avec l'IA personnalisée
        analysis_result = ai_security_service.analyze_logs_anomalies(user_logs, user_info)
        
        # Log de l'analyse
        storage.log_auth_event(
            user_id=user['id'],
            event_type="ai_analysis_personalisee",
            details=f"Analyse anomalies IA personnalisée - {len(user_logs)} logs analysés",
            success=True,
            ip_address=http_request.client.host if http_request else "unknown",
            user_agent=http_request.headers.get("user-agent", "") if http_request else "",
            risk_level="low"
        )
        
        return analysis_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur analyse anomalies IA : {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur lors de l'analyse : {str(e)}")

@security_router.post("/ai/predict-threats")
async def predict_threats(
    request: SecurityAnalysisRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    http_request: Request = None
):
    """Prédit les menaces émergentes avec l'IA"""
    try:
        token = credentials.credentials
        user = storage.get_user_by_token(token)
        
        if not user:
            raise HTTPException(status_code=401, detail="Token invalide")
        
        # Récupérer les logs historiques (7 derniers jours minimum)
        from datetime import datetime, timedelta
        cutoff = datetime.now() - timedelta(days=7)
        historical_logs = [log for log in storage.get_all_logs(limit=2000) 
                          if datetime.fromisoformat(log['timestamp']) > cutoff]
        
        # Prédire avec l'IA
        prediction_result = ai_security_service.predict_threats(historical_logs)
        
        # Log de la prédiction
        storage.log_auth_event(
            user_id=user['id'],
            event_type="ai_prediction",
            details=f"Prédiction menaces IA - {len(historical_logs)} logs analysés",
            success=True,
            ip_address=http_request.client.host if http_request else "unknown",
            user_agent=http_request.headers.get("user-agent", "") if http_request else "",
            risk_level="low"
        )
        
        return prediction_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur prédiction menaces IA : {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur lors de la prédiction : {str(e)}")

@security_router.post("/ai/recommendations")
async def get_security_recommendations(
    request: SecurityAnalysisRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    http_request: Request = None
):
    """Génère des recommandations de sécurité avec l'IA"""
    try:
        token = credentials.credentials
        user = storage.get_user_by_token(token)
        
        if not user:
            raise HTTPException(status_code=401, detail="Token invalide")
        
        # Obtenir les métriques de sécurité globales
        security_metrics = storage.get_global_security_metrics()
        
        # Générer des recommandations avec l'IA
        recommendations_result = ai_security_service.generate_security_recommendations(security_metrics)
        
        # Log des recommandations
        storage.log_auth_event(
            user_id=user['id'],
            event_type="ai_recommendations",
            details=f"Génération recommandations IA - score global : {security_metrics.get('score_global_securite', 0)}",
            success=True,
            ip_address=http_request.client.host if http_request else "unknown",
            user_agent=http_request.headers.get("user-agent", "") if http_request else "",
            risk_level="low"
        )
        
        return recommendations_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur recommandations IA : {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur lors de la génération : {str(e)}")

# === ROUTES D'ANALYSE COMPORTEMENTALE ===

@security_router.post("/behavioral/analyze")
async def analyze_behavioral_risk(
    request: BehavioralAnalysisRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    http_request: Request = None
):
    """Analyse le risque comportemental d'un utilisateur"""
    try:
        token = credentials.credentials
        user = storage.get_user_by_token(token)
        
        if not user:
            raise HTTPException(status_code=401, detail="Token invalide")
        
        # Préparer les données de la requête
        request_data = {
            "ip_address": http_request.client.host if http_request else "unknown",
            "user_agent": http_request.headers.get("user-agent", "") if http_request else "",
            "device": storage._extract_device_info(http_request.headers.get("user-agent", "")) if http_request else {},
            "country": storage._get_country_from_ip(http_request.client.host if http_request else "unknown"),
            "timestamp": datetime.now().isoformat()
        }
        
        # Analyser le risque comportemental
        risk_analysis = storage.analyze_behavioral_risk(request.user_id, request_data)
        
        # Log de l'analyse comportementale
        storage.log_auth_event(
            user_id=request.user_id,
            event_type="behavioral_analysis",
            details=f"Analyse comportementale - score risque : {risk_analysis['risk_score']}",
            success=True,
            ip_address=http_request.client.host if http_request else "unknown",
            user_agent=http_request.headers.get("user-agent", "") if http_request else "",
            risk_level=risk_analysis['risk_level']
        )
        
        return {
            "user_id": request.user_id,
            "analysis_type": "behavioral",
            "risk_analysis": risk_analysis,
            "request_context": {
                "ip_address": request_data["ip_address"],
                "device": request_data["device"],
                "country": request_data["country"]
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur analyse comportementale : {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur lors de l'analyse : {str(e)}")

# === ROUTE DASHBOARD FUSIONNÉE ===

@security_router.get("/security-dashboard")
async def get_security_dashboard_fusion(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    http_request: Request = None,
    hours: int = 24,
    min_risk_level: str = "medium"
):
    """Dashboard léger : métriques + alertes uniquement (pas d'IA ici)"""
    try:
        token = credentials.credentials
        user = storage.get_user_by_token(token)
        
        if not user:
            raise HTTPException(status_code=401, detail="Token invalide")
        
        from datetime import datetime, timedelta
        
        # 1. Métriques globales (léger)
        global_metrics = storage.get_global_security_metrics()
        
        # 2. Alertes uniquement
        alerts = storage.get_security_alerts(hours=hours, min_risk_level=min_risk_level)
        
        # Log de l'accès
        storage.log_auth_event(
            user_id=user['id'],
            event_type="access_security_dashboard",
            details=f"Dashboard rapide - {len(alerts)} alertes",
            success=True,
            ip_address=http_request.client.host if http_request else "unknown",
            user_agent=http_request.headers.get("user-agent", "") if http_request else "",
            risk_level="low"
        )
        
        return {
            "overview": {
                "security_score": global_metrics.get('score_global_securite', 0),
                "active_alerts": len(alerts),
                "active_users": global_metrics.get('activite_utilisateurs', {}).get('actifs_24h', 0)
            },
            "metrics": global_metrics,
            "alerts": {
                "items": alerts[:20],
                "total": len(alerts),
                "by_level": {
                    "critical": len([a for a in alerts if a['risk_level'] == 'critical']),
                    "high": len([a for a in alerts if a['risk_level'] == 'high']),
                    "medium": len([a for a in alerts if a['risk_level'] == 'medium'])
                }
            },
            "ai_routes_available": [
                "POST /ai/analyze-anomalies",
                "POST /ai/predict-threats", 
                "POST /ai/recommendations"
            ],
            "filters": {
                "hours": hours,
                "min_risk_level": min_risk_level
            },
            "generated_at": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur dashboard : {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur serveur")

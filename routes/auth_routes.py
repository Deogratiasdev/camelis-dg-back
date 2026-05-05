from fastapi import APIRouter, HTTPException, Depends, Request, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
from json_storage import storage
from services.email_service import email_service
import logging
import hashlib
from datetime import datetime
import os
import uuid

logger = logging.getLogger(__name__)
auth_router = APIRouter()
security = HTTPBearer()

def generate_device_fingerprint(request: Request) -> str:
    """Génère un fingerprint de device basique"""
    user_agent = request.headers.get("user-agent", "")
    ip = request.client.host if request.client else "unknown"
    return hashlib.md5(f"{ip}_{user_agent}".encode()).hexdigest()[:16]

class UserRegister(BaseModel):
    email: str
    password: str
    first_name: str
    last_name: str

class UserResponse(BaseModel):
    id: str
    email: str
    first_name: str
    last_name: str
    group: str
    message: str

class OTPRequest(BaseModel):
    email: str

class OTPVerify(BaseModel):
    email: str
    code: str

class LoginRequest(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    token: str
    user_id: str
    email: str
    first_name: str
    last_name: str
    group: str
    message: str

class UpdateProfileRequest(BaseModel):
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None

@auth_router.post("/register", response_model=UserResponse)
async def register_user(user: UserRegister, request: Request):
    """Inscription d'un nouvel utilisateur"""
    try:
        # Créer l'utilisateur via le storage
        new_user = storage.create_user(
            email=user.email,
            password=user.password,
            first_name=user.first_name,
            last_name=user.last_name
        )
        
        if not new_user:
            # Log de l'échec
            storage.log_auth_event(
                user_id=None,
                event_type="register",
                details=f"Email déjà utilisé: {user.email}",
                success=False,
                ip_address=request.client.host if request.client else "unknown",
                user_agent=request.headers.get("user-agent", ""),
                risk_level="medium"
            )
            raise HTTPException(status_code=400, detail="Cet email est déjà utilisé")
        
        # Log du succès
        storage.log_auth_event(
            user_id=new_user["id"],
            event_type="register",
            details=f"Nouveau compte créé: {user.email}",
            success=True,
            ip_address=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", ""),
            risk_level="low"
        )
        
        logger.info(f"Nouvel utilisateur inscrit: {user.email}")
        
        return UserResponse(
            id=new_user["id"],
            email=new_user["email"],
            first_name=new_user["first_name"],
            last_name=new_user["last_name"],
            group=new_user.get("group", "Utilisateur"),
            message="Inscription réussie. Veuillez vérifier votre compte avec le code OTP."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        # Log de l'erreur
        storage.log_auth_event(
            user_id=None,
            event_type="register",
            details=f"Erreur inscription: {str(e)}",
            success=False,
            ip_address=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", ""),
            device_fingerprint=generate_device_fingerprint(request)
        )
        logger.error(f"Erreur inscription: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur lors de l'inscription: {str(e)}")

@auth_router.post("/request-otp")
async def request_otp(request: OTPRequest, http_request: Request):
    """Demande un code OTP pour vérifier le compte"""
    try:
        user = storage.get_user_by_email(request.email)
        if not user:
            # Log de l'échec
            storage.log_auth_event(
                user_id=None,
                event_type="request_otp",
                details=f"Tentative OTP email inexistant: {request.email}",
                success=False,
                ip_address=http_request.client.host if http_request.client else "unknown",
                user_agent=http_request.headers.get("user-agent", ""),
                risk_level="medium"
            )
            raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
        
        if user.get('is_verified', False):
            # Log de l'échec
            storage.log_auth_event(
                user_id=user['id'],
                event_type="request_otp",
                details=f"Tentative OTP pour compte déjà vérifié: {request.email}",
                success=False,
                ip_address=http_request.client.host if http_request.client else "unknown",
                user_agent=http_request.headers.get("user-agent", ""),
                device_fingerprint=generate_device_fingerprint(http_request)
            )
            raise HTTPException(status_code=400, detail="Compte déjà vérifié")
        
        # Générer et envoyer l'OTP
        otp_code = storage.generate_otp(user['id'])
        
        # ENVOI EMAIL BREVO
        email_sent = email_service.send_otp_email(
            to_email=request.email,
            otp_code=otp_code,
            first_name=user.get('first_name')
        )
        
        # Log du succès
        storage.log_auth_event(
            user_id=user['id'],
            event_type="request_otp",
            details=f"OTP généré et envoyé par email: {request.email} (email_sent: {email_sent})",
            success=True,
            ip_address=http_request.client.host if http_request.client else "unknown",
            user_agent=http_request.headers.get("user-agent", "") if http_request else "",
            risk_level="low"
        )
        
        response_data = {
            "message": "Code OTP envoyé avec succès" if email_sent else "Code OTP généré (mode développement - email non envoyé)",
            "email": request.email,
            "expires_in": "10 minutes"
        }
        
        # En mode développement uniquement, si l'email n'est pas envoyé
        if not email_sent:
            response_data["otp_for_testing"] = otp_code
            
        return response_data
        
    except HTTPException:
        raise
    except Exception as e:
        # Log de l'erreur
        storage.log_auth_event(
            user_id=None,
            event_type="request_otp",
            details=f"Erreur demande OTP: {str(e)}",
            success=False,
            ip_address=http_request.client.host if http_request.client else "unknown",
            user_agent=http_request.headers.get("user-agent", ""),
            device_fingerprint=generate_device_fingerprint(http_request)
        )
        logger.error(f"Erreur demande OTP: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur lors de la demande OTP: {str(e)}")

@auth_router.post("/verify-otp")
async def verify_otp(request: OTPVerify, http_request: Request):
    """Vérifie un code OTP"""
    try:
        user = storage.get_user_by_email(request.email)
        if not user:
            # Log de l'échec
            storage.log_auth_event(
                user_id=None,
                event_type="verify_otp",
                details=f"Tentative vérification OTP pour email inexistant: {request.email}",
                success=False,
                ip_address=http_request.client.host if http_request.client else "unknown",
                user_agent=http_request.headers.get("user-agent", ""),
                device_fingerprint=generate_device_fingerprint(http_request)
            )
            raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
        
        if user.get('is_verified', False):
            # Log de l'échec
            storage.log_auth_event(
                user_id=user['id'],
                event_type="verify_otp",
                details=f"Tentative vérification OTP pour compte déjà vérifié: {request.email}",
                success=False,
                ip_address=http_request.client.host if http_request.client else "unknown",
                user_agent=http_request.headers.get("user-agent", ""),
                device_fingerprint=generate_device_fingerprint(http_request)
            )
            raise HTTPException(status_code=400, detail="Compte déjà vérifié")
        
        # Valider l'OTP
        if storage.validate_otp(user['id'], request.code):
            # Log du succès
            storage.log_auth_event(
                user_id=user['id'],
                event_type="verify_otp",
                details=f"OTP validé avec succès pour {request.email}",
                success=True,
                ip_address=http_request.client.host if http_request.client else "unknown",
                user_agent=http_request.headers.get("user-agent", ""),
                device_fingerprint=generate_device_fingerprint(http_request)
            )
            logger.info(f"Compte vérifié: {request.email}")
            return {"message": "Compte vérifié avec succès"}
        else:
            # Log de l'échec
            storage.log_auth_event(
                user_id=user['id'],
                event_type="verify_otp",
                details=f"OTP invalide/expire: {request.code}",
                success=False,
                ip_address=http_request.client.host if http_request.client else "unknown",
                user_agent=http_request.headers.get("user-agent", ""),
                risk_level="high"
            )
            raise HTTPException(status_code=400, detail="Code OTP invalide ou expiré")
        
    except HTTPException:
        raise
    except Exception as e:
        # Log de l'erreur
        storage.log_auth_event(
            user_id=None,
            event_type="verify_otp",
            details=f"Erreur vérification OTP: {str(e)}",
            success=False,
            ip_address=http_request.client.host if http_request.client else "unknown",
            user_agent=http_request.headers.get("user-agent", ""),
            device_fingerprint=generate_device_fingerprint(http_request)
        )
        logger.error(f"Erreur vérification OTP: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur lors de la vérification OTP: {str(e)}")

@auth_router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, http_request: Request):
    """Connexion avec JWT"""
    try:
        user = storage.get_user_by_email(request.email)
        if not user:
            # Log de l'échec
            storage.log_auth_event(
                user_id=None,
                event_type="login",
                details=f"Email inexistant: {request.email}",
                success=False,
                ip_address=http_request.client.host if http_request.client else "unknown",
                user_agent=http_request.headers.get("user-agent", ""),
                risk_level="medium"
            )
            raise HTTPException(status_code=401, detail="Identifiants incorrects")
        
        # Vérifier si le compte est vérifié
        if not user.get('is_verified', False):
            # Log de l'échec
            storage.log_auth_event(
                user_id=user['id'],
                event_type="login",
                details=f"Compte non vérifié: {request.email}",
                success=False,
                ip_address=http_request.client.host if http_request.client else "unknown",
                user_agent=http_request.headers.get("user-agent", ""),
                risk_level="medium"
            )
            raise HTTPException(status_code=403, detail="Compte non vérifié. Veuillez d'abord vérifier votre compte avec un code OTP.")
        
        # Vérifier le mot de passe
        if not storage.verify_password(request.password, user['password_hash']):
            # Log de l'échec
            storage.log_auth_event(
                user_id=user['id'],
                event_type="login",
                details=f"Mot de passe incorrect: {request.email}",
                success=False,
                ip_address=http_request.client.host if http_request.client else "unknown",
                user_agent=http_request.headers.get("user-agent", ""),
                risk_level="high"
            )
            raise HTTPException(status_code=401, detail="Identifiants incorrects")
        
        # Créer la session JWT
        token = storage.create_session(user['id'])
        
        # Log du succès
        storage.log_auth_event(
            user_id=user['id'],
            event_type="login",
            details=f"Connexion réussie: {request.email}",
            success=True,
            ip_address=http_request.client.host if http_request.client else "unknown",
            user_agent=http_request.headers.get("user-agent", ""),
            risk_level="low"
        )
        
        logger.info(f"Connexion réussie: {request.email}")
        
        return {
            "message": "Connexion réussie",
            "token": token,
            "user_id": user['id'],
            "email": user['email'],
            "first_name": user.get('first_name', ''),
            "last_name": user.get('last_name', ''),
            "group": user.get('group', 'Utilisateur')
        }
        
    except HTTPException:
        raise
    except Exception as e:
        # Log de l'erreur
        storage.log_auth_event(
            user_id=None,
            event_type="login",
            details=f"Erreur connexion: {str(e)}",
            success=False,
            ip_address=http_request.client.host if http_request.client else "unknown",
            user_agent=http_request.headers.get("user-agent", ""),
            device_fingerprint=generate_device_fingerprint(http_request)
        )
        logger.error(f"Erreur connexion: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur lors de la connexion: {str(e)}")

def _get_security_recommendations(summary):
    """Génère des recommandations de sécurité basées sur le résumé"""
    recommendations = []
    
    if summary['security_score'] < 70:
        recommendations.append("Votre score de sécurité est faible. Vérifiez vos activités récentes.")
    
    if summary['failed_attempts'] > 3:
        recommendations.append("Plusieurs tentatives de connexion échouées détectées. Changez votre mot de passe.")
    
    if summary['unique_ips'] > 3:
        recommendations.append("Connexions depuis plusieurs adresses IP. Vérifiez que c'est bien vous.")
    
    if summary['high_risk_events'] > 0:
        recommendations.append("Événements à risque élevé détectés. Activez l'authentification à deux facteurs si possible.")
    
    if summary['recent_activity_24h'] > 10:
        recommendations.append("Activité intense détectée. Vérifiez que toutes les connexions sont légitimes.")
    
    return recommendations

@auth_router.get("/my-security")
async def get_my_security(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    request: Request = None,
    include_logs: bool = True,
    logs_limit: int = 20,
    alerts_hours: int = 24,
    alerts_min_risk: str = "medium"
):
    """Route fusionnée : profil + logs + résumé sécurité + alertes personnelles"""
    try:
        token = credentials.credentials
        user = storage.get_user_by_token(token)
        
        if not user:
            storage.log_auth_event(
                user_id=None,
                event_type="access_my_security",
                details="Tentative accès /my-security avec token invalide",
                success=False,
                ip_address=request.client.host if request else "unknown",
                user_agent=request.headers.get("user-agent", "") if request else "",
                risk_level="medium"
            )
            raise HTTPException(status_code=401, detail="Token invalide")
        
        # 1. Profil utilisateur
        profile = {
            "id": user['id'],
            "email": user['email'],
            "first_name": user.get('first_name', ''),
            "last_name": user.get('last_name', ''),
            "group": user.get('group', 'Utilisateur'),
            "is_verified": user.get('is_verified', False),
            "created_at": user.get('created_at', '')
        }
        
        # 2. Résumé de sécurité
        security_summary = storage.get_user_security_summary(user['id'])
        recommendations = _get_security_recommendations(security_summary)
        
        # 3. Logs personnels (si demandé)
        logs = []
        if include_logs:
            logs = storage.get_user_logs(user['id'], limit=logs_limit)
        
        # 4. Alertes récentes concernant l'utilisateur
        all_alerts = storage.get_security_alerts(hours=alerts_hours, min_risk_level=alerts_min_risk)
        user_alerts = [a for a in all_alerts if a.get('user_id') == user['id']]
        
        # Log de l'accès
        storage.log_auth_event(
            user_id=user['id'],
            event_type="access_my_security",
            details=f"Accès résumé sécurité complet - {len(logs)} logs, {len(user_alerts)} alertes",
            success=True,
            ip_address=request.client.host if request else "unknown",
            user_agent=request.headers.get("user-agent", "") if request else "",
            risk_level="low"
        )
        
        return {
            "profile": profile,
            "security": {
                "score": security_summary.get('security_score', 0),
                "summary": security_summary,
                "recommendations": recommendations
            },
            "activity": {
                "logs": logs,
                "logs_count": len(logs),
                "recent_alerts": user_alerts,
                "alerts_count": len(user_alerts)
            },
            "meta": {
                "generated_at": datetime.now().isoformat(),
                "filters": {
                    "logs_limit": logs_limit,
                    "alerts_hours": alerts_hours,
                    "alerts_min_risk": alerts_min_risk
                }
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur /my-security: {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur serveur")

@auth_router.post("/update-profile")
async def update_profile(
    profile_data: UpdateProfileRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    request: Request = None
):
    """
    Modification du profil.
    """
    try:
        token = credentials.credentials
        
        user = storage.get_user_by_token(token)
        if not user:
            raise HTTPException(status_code=401, detail="Token invalide")
        
        # Préparer les mises à jour
        updates = {}
        if profile_data.email:
            updates['email'] = profile_data.email
        if profile_data.first_name:
            updates['first_name'] = profile_data.first_name
        if profile_data.last_name:
            updates['last_name'] = profile_data.last_name
        
        # Changement mot de passe
        if profile_data.new_password:
            if not profile_data.current_password:
                raise HTTPException(status_code=400, detail="Mot de passe actuel requis")
            
            if not storage.verify_password(profile_data.current_password, user['password_hash']):
                storage.log_auth_event(
                    user_id=user['id'],
                    event_type="password_change_failed",
                    details="Mot de passe actuel incorrect",
                    success=False,
                    risk_level="high"
                )
                raise HTTPException(status_code=401, detail="Mot de passe actuel incorrect")
            
            updates['password'] = profile_data.new_password
        
        # Appliquer les mises à jour
        updated_user = storage.update_user(user['id'], **updates)
        
        if not updated_user:
            raise HTTPException(status_code=500, detail="Erreur lors de la mise à jour")
        
        # Log succès
        storage.log_auth_event(
            user_id=user['id'],
            event_type="profile_updated",
            details=f"Profil modifié: {list(updates.keys())}",
            success=True,
            ip_address=request.client.host if request else "unknown",
            user_agent=request.headers.get("user-agent", "") if request else "",
            risk_level="medium"
        )
        
        return {
            "message": "Profil mis à jour avec succès",
            "updated_fields": list(updates.keys()),
            "profile": {
                "id": updated_user['id'],
                "email": updated_user['email'],
                "first_name": updated_user.get('first_name', ''),
                "last_name": updated_user.get('last_name', ''),
                "group": updated_user.get('group', 'Utilisateur')
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur mise à jour profil: {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur serveur")

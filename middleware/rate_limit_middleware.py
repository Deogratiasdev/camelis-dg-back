import time
import os
import hashlib
from typing import Dict, Optional
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from collections import defaultdict, deque
import logging

logger = logging.getLogger(__name__)

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting personnalisable par utilisateur"""
    
    def __init__(self, app):
        super().__init__(app)
        self.requests: Dict[str, deque] = defaultdict(lambda: deque())
        self.auth_attempts: Dict[str, deque] = defaultdict(lambda: deque())
        
    async def dispatch(self, request: Request, call_next):
        # Récupérer l'IP du client
        client_ip = self.get_client_ip(request)
        
        # Vérifier si c'est une route d'authentification
        if self.is_auth_route(request.url.path):
            await self.check_auth_rate_limit(client_ip, request)
        else:
            await self.check_general_rate_limit(client_ip, request)
        
        response = await call_next(request)
        return response
    
    def get_client_ip(self, request: Request) -> str:
        """Récupère l'IP réelle du client"""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    def is_auth_route(self, path: str) -> bool:
        """Vérifie si c'est une route d'authentification"""
        auth_routes = [
            "/auth/register",
            "/auth/request-otp",
            "/auth/verify-otp",
            "/auth/login"
        ]
        return any(path.startswith(route) for route in auth_routes)
    
    async def check_auth_rate_limit(self, client_ip: str, request: Request):
        """Vérifie le rate limiting pour l'authentification"""
        try:
            # Récupérer les limites (simplifié - uniquement les limites par défaut)
            limits = self.get_default_limits()
            
            current_time = time.time()
            attempt_times = self.auth_attempts[client_ip]
            
            # Nettoyer les anciennes tentatives
            window_seconds = limits['auth_window_minutes'] * 60
            window_start = current_time - window_seconds
            
            while attempt_times and attempt_times[0] < window_start:
                attempt_times.popleft()
            
            # Ajouter la tentative actuelle
            attempt_times.append(current_time)
            
            # Vérifier la limite
            recent_attempts = len(attempt_times)
            
            if recent_attempts > limits['auth_max_attempts']:
                logger.warning(f"Rate limit auth dépassé pour IP {client_ip}: {recent_attempts}/{limits['auth_max_attempts']} en {limits['auth_window_minutes']}min")
                raise HTTPException(
                    status_code=429,
                    detail=f"Trop de tentatives. Limite: {limits['auth_max_attempts']} tentatives par {limits['auth_window_minutes']} minutes",
                    headers={
                        "Retry-After": str(window_seconds),
                        "X-Auth-RateLimit-Limit": str(limits['auth_max_attempts']),
                        "X-Auth-RateLimit-Remaining": "0",
                        "X-Auth-RateLimit-Reset": str(int(current_time + window_seconds)),
                        "X-RateLimit-Type": "default"
                    }
                )
                
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Erreur vérification rate limit auth: {str(e)}")
            # En cas d'erreur, continuer sans rate limiting
            pass
    
    async def check_general_rate_limit(self, client_ip: str, request: Request):
        """Vérifie le rate limiting général"""
        try:
            limits = self.get_default_limits()
            
            current_time = time.time()
            request_times = self.requests[client_ip]
            
            # Nettoyer les anciennes requêtes
            one_hour_ago = current_time - 3600
            while request_times and request_times[0] < one_hour_ago:
                request_times.popleft()
            
            # Ajouter la requête actuelle
            request_times.append(current_time)
            
            # Vérifier la limite horaire
            if len(request_times) > limits['requests_per_hour']:
                logger.warning(f"Rate limit horaire dépassé pour IP {client_ip}: {len(request_times)}/{limits['requests_per_hour']}")
                raise HTTPException(
                    status_code=429,
                    detail=f"Trop de requêtes. Limite: {limits['requests_per_hour']} par heure",
                    headers={
                        "Retry-After": "3600",
                        "X-RateLimit-Limit": str(limits['requests_per_hour']),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(current_time + 3600)),
                        "X-RateLimit-Type": "default"
                    }
                )
                
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Erreur vérification rate limit général: {str(e)}")
            # En cas d'erreur, continuer sans rate limiting
            pass
    
    def get_default_limits(self) -> Dict[str, int]:
        """Retourne les limites par défaut depuis les variables d'environnement"""
        return {
            'requests_per_hour': int(os.getenv("RATE_LIMIT_REQUESTS_PER_HOUR", "1000")),
            'auth_max_attempts': int(os.getenv("RATE_LIMIT_AUTH_MAX_ATTEMPTS", "5")),
            'auth_window_minutes': int(os.getenv("RATE_LIMIT_AUTH_WINDOW_MINUTES", "15"))
        }

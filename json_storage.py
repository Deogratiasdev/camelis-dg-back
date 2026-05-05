import json
import hashlib
import uuid
import secrets
import pytz
from datetime import datetime, timedelta
import os
import jwt as PyJWT
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

class JSONStorage:
    """Classe de stockage JSON simple"""
    
    def __init__(self):
        self.data_dir = 'data'
        self.users_file = os.path.join(self.data_dir, 'users.json')
        self.sessions_file = os.path.join(self.data_dir, 'sessions.json')
        self.auth_logs_file = os.path.join(self.data_dir, 'auth_logs.json')
        self.otp_codes_file = os.path.join(self.data_dir, 'otp_codes.json')
        self.rate_limits_file = os.path.join(self.data_dir, 'rate_limits.json')
        self.ai_analyses_file = os.path.join(self.data_dir, 'ai_analyses.json')
        
        # Charger la clé JWT depuis l'environnement
        self.jwt_secret = os.getenv("JWT_SECRET_KEY", "default_secret_change_in_production")
        
        # Créer le dossier data s'il n'existe pas
        os.makedirs(self.data_dir, exist_ok=True)

    def _normalize_user(self, user):
        """Garantit la présence des champs attendus par le front."""
        if not user:
            return user

        user.setdefault("first_name", "")
        user.setdefault("last_name", "")
        user.setdefault("email", "")
        user.setdefault("group", "Utilisateur")
        user.setdefault("created_at", "")
        user.setdefault("is_verified", False)
        return user
    
    def _read_json(self, filepath):
        """Lit un fichier JSON"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []
    
    def _write_json(self, filepath, data):
        """Écrit dans un fichier JSON"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    # === UTILISATEURS ===
    
    def create_user(self, email, password, first_name, last_name):
        """Crée un nouvel utilisateur"""
        users = self._read_json(self.users_file)
        
        # Vérifier si l'email existe déjà
        if any(user['email'] == email for user in users):
            return None
        
        new_user = {
            "id": str(uuid.uuid4()),
            "email": email,
            "password_hash": hashlib.sha256(password.encode()).hexdigest(),
            "first_name": first_name,
            "last_name": last_name,
            "group": "Utilisateur",
            "created_at": datetime.now().isoformat(),
            "is_verified": False,
            "failed_attempts": 0,
            "locked_until": None
        }
        
        users.append(new_user)
        self._write_json(self.users_file, users)
        return new_user
    
    def get_user_by_email(self, email):
        """Récupère un utilisateur par email"""
        users = self._read_json(self.users_file)
        for user in users:
            if user['email'] == email:
                return self._normalize_user(user)
        return None
    
    def verify_password(self, password, hashed):
        """Vérifie un mot de passe"""
        return hashlib.sha256(password.encode()).hexdigest() == hashed
    
    # === OTP ===
    
    def generate_otp(self, user_id):
        """Génère un code OTP de 6 chiffres"""
        otp_codes = self._read_json(self.otp_codes_file)
        
        # Supprimer les anciens OTP pour cet utilisateur
        otp_codes = [otp for otp in otp_codes if otp['user_id'] != user_id or 
                    datetime.fromisoformat(otp['expires_at']) > datetime.now()]
        
        # Générer nouveau OTP
        code = f"{secrets.randbelow(1000000):06d}"
        otp = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "code": code,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(minutes=10)).isoformat(),
            "used": False
        }
        
        otp_codes.append(otp)
        self._write_json(self.otp_codes_file, otp_codes)
        return code
    
    def validate_otp(self, user_id, code):
        """Valide un code OTP"""
        otp_codes = self._read_json(self.otp_codes_file)
        now = datetime.now()
        
        for otp in otp_codes:
            if (otp['user_id'] == user_id and 
                otp['code'] == code and 
                not otp['used'] and
                datetime.fromisoformat(otp['expires_at']) > now):
                
                # Marquer comme utilisé
                otp['used'] = True
                self._write_json(self.otp_codes_file, otp_codes)
                
                # Marquer l'utilisateur comme vérifié
                self.verify_user(user_id)
                return True
        
        return False
    
    def verify_user(self, user_id):
        """Marque un utilisateur comme vérifié"""
        users = self._read_json(self.users_file)
        for user in users:
            if user['id'] == user_id:
                user['is_verified'] = True
                self._write_json(self.users_file, users)
                break
    
    def update_user(self, user_id, **kwargs):
        """Met à jour un utilisateur"""
        users = self._read_json(self.users_file)
        for user in users:
            if user['id'] == user_id:
                if 'email' in kwargs:
                    user['email'] = kwargs['email']
                if 'first_name' in kwargs:
                    user['first_name'] = kwargs['first_name']
                if 'last_name' in kwargs:
                    user['last_name'] = kwargs['last_name']
                if 'group' in kwargs:
                    user['group'] = kwargs['group']
                if 'password' in kwargs:
                    user['password_hash'] = self._hash_password(kwargs['password'])
                self._normalize_user(user)
                self._write_json(self.users_file, users)
                return user
        return None
    
    # === SESSIONS JWT ===
    
    def create_session(self, user_id):
        """Crée une session JWT"""
        payload = {
            'user_id': user_id,
            'exp': datetime.now(pytz.utc) + timedelta(hours=24),
            'iat': datetime.now(pytz.utc)
        }
        
        token = PyJWT.encode(payload, self.jwt_secret, algorithm='HS256')
        
        # Sauvegarder la session
        sessions = self._read_json(self.sessions_file)
        session = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "token_hash": hashlib.sha256(token.encode()).hexdigest(),
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=24)).isoformat(),
            "is_active": True
        }
        
        sessions.append(session)
        self._write_json(self.sessions_file, sessions)
        
        return token
    
    def validate_token(self, token):
        """Valide un token JWT"""
        try:
            payload = PyJWT.decode(token, self.jwt_secret, algorithms=['HS256'])
            return payload
        except PyJWT.ExpiredSignatureError:
            return None
        except PyJWT.InvalidTokenError:
            return None
    
    def get_user_by_token(self, token):
        """Récupère un utilisateur à partir d'un token"""
        payload = self.validate_token(token)
        if not payload:
            return None
        
        user_id = payload['user_id']
        users = self._read_json(self.users_file)
        for user in users:
            if user['id'] == user_id:
                return self._normalize_user(user)
        return None
    
    def invalidate_token(self, token):
        """Invalide un token en supprimant sa session"""
        sessions = self._read_json(self.sessions_file)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        sessions = [s for s in sessions if s['token_hash'] != token_hash]
        self._write_json(self.sessions_file, sessions)
    
    # === RATE LIMITING ===
    
    def get_user_rate_limits(self, user_id):
        """Récupère les limites de rate personnalisées d'un utilisateur"""
        rate_limits = self._read_json(self.rate_limits_file)
        return rate_limits.get(user_id)
    
    def set_user_rate_limits(self, user_id, limits):
        """Définit les limites de rate personnalisées"""
        rate_limits = self._read_json(self.rate_limits_file)
        rate_limits[user_id] = limits
        self._write_json(self.rate_limits_file, rate_limits)
        return True
    
    # === LOGS ===
    
    def log_auth_event(self, user_id, event_type, details, success, ip_address, user_agent, device_fingerprint=None, risk_level="low", location=None):
        """Enregistre un événement d'authentification essentiel"""
        logs = self._read_json(self.auth_logs_file)
        
        # Calculer le niveau de risque automatiquement si non spécifié
        if risk_level == "auto":
            risk_level = self._calculate_risk_level(event_type, success, ip_address, details)
        
        log_entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "success": success,
            "risk_level": risk_level,  # low, medium, high, critical
            "ip_address": ip_address,
            "country": self._get_country_from_ip(ip_address),
            "device": self._extract_device_info(user_agent),
            "location": location,
            "details": details,
            "session_id": self._get_active_session_id(user_id) if user_id else None
        }
        
        logs.append(log_entry)
        
        # Garder seulement les 500 derniers logs (plus pertinent)
        if len(logs) > 500:
            logs = logs[-500:]
        
        self._write_json(self.auth_logs_file, logs)
        return log_entry
    
    def _calculate_risk_level(self, event_type, success, ip_address, details):
        """Calcule automatiquement le niveau de risque"""
        if not success:
            if "mot de passe incorrect" in details.lower() or "otp invalide" in details.lower():
                return "high"
            elif "email inexistant" in details.lower():
                return "medium"
            else:
                return "low"
        
        # Événements réussis mais potentiellement suspects
        if event_type == "login" and self._is_suspicious_ip(ip_address):
            return "medium"
        
        return "low"
    
    def _get_country_from_ip(self, ip_address):
        """Extrait le pays depuis l'IP (simulation)"""
        # En production, utiliser une vraie API de géolocalisation
        if ip_address.startswith("127.0.0.1") or ip_address.startswith("192.168."):
            return "Local"
        elif ip_address.startswith("8.8."):
            return "US"
        else:
            return "Unknown"
    
    def _extract_device_info(self, user_agent):
        """Extrait les informations essentielles du device"""
        if not user_agent:
            return {"type": "unknown"}
        
        device_info = {"type": "unknown"}
        
        if "Windows" in user_agent:
            device_info["os"] = "Windows"
        elif "Mac" in user_agent or "Macintosh" in user_agent:
            device_info["os"] = "macOS"
        elif "Linux" in user_agent:
            device_info["os"] = "Linux"
        elif "Android" in user_agent:
            device_info["os"] = "Android"
        elif "iPhone" in user_agent or "iPad" in user_agent:
            device_info["os"] = "iOS"
        
        if "Chrome" in user_agent:
            device_info["browser"] = "Chrome"
        elif "Firefox" in user_agent:
            device_info["browser"] = "Firefox"
        elif "Safari" in user_agent:
            device_info["browser"] = "Safari"
        elif "Edge" in user_agent:
            device_info["browser"] = "Edge"
        
        return device_info
    
    def _is_suspicious_ip(self, ip_address):
        """Détecte les IPs suspectes (simulation)"""
        # En production, utiliser une vraie liste noire ou service de réputation
        suspicious_ranges = ["10.0.0.", "192.168.1.", "172.16.0."]
        return any(ip_address.startswith(range_) for range_ in suspicious_ranges)
    
    def _get_active_session_id(self, user_id):
        """Récupère l'ID de session active d'un utilisateur"""
        sessions = self._read_json(self.sessions_file)
        now = datetime.now()
        
        for session in sessions:
            if (session['user_id'] == user_id and 
                session.get('is_active', False) and
                datetime.fromisoformat(session['expires_at']) > now):
                return session['id']
        
        return None
    
    def get_user_logs(self, user_id, limit=50, event_type=None):
        """Récupère les logs d'un utilisateur"""
        logs = self._read_json(self.auth_logs_file)
        
        # Filtrer par utilisateur
        user_logs = [log for log in logs if log['user_id'] == user_id]
        
        # Filtrer par type d'événement si spécifié
        if event_type:
            user_logs = [log for log in user_logs if log['event_type'] == event_type]
        
        # Trier par date décroissante
        user_logs.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Limiter le nombre de résultats
        return user_logs[:limit]
    
    def get_all_logs(self, limit=100, event_type=None, success_only=None):
        """Récupère tous les logs (pour admin)"""
        logs = self._read_json(self.auth_logs_file)
        
        # Filtrer par type d'événement si spécifié
        if event_type:
            logs = [log for log in logs if log['event_type'] == event_type]
        
        # Filtrer par succès/échec si spécifié
        if success_only is not None:
            logs = [log for log in logs if log['success'] == success_only]
        
        # Trier par date décroissante
        logs.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Limiter le nombre de résultats
        return logs[:limit]
    
    def get_security_alerts(self, hours=24, min_risk_level="medium"):
        """Récupère les alertes de sécurité récentes"""
        logs = self._read_json(self.auth_logs_file)
        now = datetime.now()
        cutoff_time = now - timedelta(hours=hours)
        
        alerts = []
        for log in logs:
            # Filtrer par date
            log_time = datetime.fromisoformat(log['timestamp'])
            if log_time < cutoff_time:
                continue
            
            # Filtrer par niveau de risque
            risk_levels = ["low", "medium", "high", "critical"]
            if risk_levels.index(log['risk_level']) < risk_levels.index(min_risk_level):
                continue
            
            # Filtrer les événements pertinents pour la sécurité
            security_events = ["login", "verify_otp", "register", "request_otp"]
            if log['event_type'] not in security_events:
                continue
            
            alerts.append(log)
        
        # Trier par risque puis par date
        alerts.sort(key=lambda x: (
            -risk_levels.index(x['risk_level']),
            x['timestamp']
        ), reverse=True)
        
        return alerts
    
    def get_user_security_summary(self, user_id):
        """Génère un résumé de sécurité pour un utilisateur"""
        logs = self._read_json(self.auth_logs_file)
        user_logs = [log for log in logs if log['user_id'] == user_id]
        
        # Statistiques
        total_logs = len(user_logs)
        failed_attempts = len([log for log in user_logs if not log['success']])
        high_risk_events = len([log for log in user_logs if log['risk_level'] in ['high', 'critical']])
        
        # IPs utilisées
        ips = list(set([log['ip_address'] for log in user_logs]))
        countries = list(set([log.get('country', 'Unknown') for log in user_logs]))
        
        # Devices utilisés
        devices = []
        for log in user_logs:
            if 'device' in log and log['device']:
                device_str = f"{log['device'].get('os', 'Unknown')} - {log['device'].get('browser', 'Unknown')}"
                if device_str not in devices:
                    devices.append(device_str)
        
        # Événements récents (24h)
        now = datetime.now()
        recent_logs = [log for log in user_logs 
                      if datetime.fromisoformat(log['timestamp']) > now - timedelta(hours=24)]
        
        return {
            "user_id": user_id,
            "total_events": total_logs,
            "failed_attempts": failed_attempts,
            "success_rate": (total_logs - failed_attempts) / max(total_logs, 1) * 100,
            "high_risk_events": high_risk_events,
            "unique_ips": len(ips),
            "unique_countries": len(countries),
            "unique_devices": len(devices),
            "recent_activity_24h": len(recent_logs),
            "last_activity": user_logs[0]['timestamp'] if user_logs else None,
            "security_score": self._calculate_security_score(failed_attempts, high_risk_events, len(ips))
        }
    
    def _calculate_security_score(self, failed_attempts, high_risk_events, unique_ips):
        """Calcule un score de sécurité (0-100)"""
        score = 100
        
        # Pénalités pour les tentatives échouées
        score -= min(failed_attempts * 5, 30)
        
        # Pénalités pour les événements à risque élevé
        score -= min(high_risk_events * 10, 40)
        
        # Pénalités pour trop d'IPs différentes
        if unique_ips > 3:
            score -= (unique_ips - 3) * 5
        
        return max(0, min(100, score))
    
    # === ANALYSE COMPORTEMENTALE ===
    
    def analyze_behavioral_risk(self, user_id, request_data):
        """Analyse le risque comportemental pour un utilisateur"""
        logs = self._read_json(self.auth_logs_file)
        user_logs = [log for log in logs if log['user_id'] == user_id]
        
        if not user_logs:
            return {"risk_score": 50, "factors": [], "recommendation": "Données insuffisantes"}
        
        risk_factors = []
        risk_score = 50  # Score de base
        
        # 1. Analyse des IPs
        current_ip = request_data.get('ip_address', 'unknown')
        user_ips = list(set([log.get('ip_address', '') for log in user_logs]))
        
        if current_ip not in user_ips and len(user_ips) > 0:
            risk_factors.append({
                "type": "nouvelle_ip",
                "severity": "medium",
                "description": f"Nouvelle IP : {current_ip} (précédemment : {', '.join(user_ips[:3])})"
            })
            risk_score += 15
        
        if len(user_ips) > 5:
            risk_factors.append({
                "type": "multiples_ips",
                "severity": "high",
                "description": f"Trop d'IPs différentes : {len(user_ips)}"
            })
            risk_score += 25
        
        # 2. Analyse des devices
        current_device = request_data.get('device', {})
        user_devices = []
        for log in user_logs:
            if log.get('device'):
                device_str = f"{log['device'].get('os', 'Unknown')}-{log['device'].get('browser', 'Unknown')}"
                user_devices.append(device_str)
        
        user_devices = list(set(user_devices))
        current_device_str = f"{current_device.get('os', 'Unknown')}-{current_device.get('browser', 'Unknown')}"
        
        if current_device_str not in user_devices and len(user_devices) > 0:
            risk_factors.append({
                "type": "nouveau_device",
                "severity": "medium",
                "description": f"Nouveau device : {current_device_str}"
            })
            risk_score += 10
        
        # 3. Analyse temporelle
        current_time = datetime.now()
        current_hour = current_time.hour
        
        # Heures de connexion habituelles
        connection_hours = []
        for log in user_logs:
            try:
                log_time = datetime.fromisoformat(log['timestamp'])
                connection_hours.append(log_time.hour)
            except:
                continue
        
        if connection_hours:
            hour_frequency = {}
            for hour in connection_hours:
                hour_frequency[hour] = hour_frequency.get(hour, 0) + 1
            
            # Si connexion en dehors des heures habituelles (21h-6h)
            if current_hour < 6 or current_hour > 21:
                if current_hour not in hour_frequency or hour_frequency[current_hour] < max(hour_frequency.values()) * 0.1:
                    risk_factors.append({
                        "type": "heure_inhabituelle",
                        "severity": "low",
                        "description": f"Connexion à {current_hour}h (heures habituelles : {max(hour_frequency, key=hour_frequency.get)}h)"
                    })
                    risk_score += 5
        
        # 4. Analyse des pays
        current_country = request_data.get('country', 'Unknown')
        user_countries = list(set([log.get('country', 'Unknown') for log in user_logs]))
        
        if current_country not in user_countries and len(user_countries) > 0 and current_country != 'Unknown':
            risk_factors.append({
                "type": "nouveau_pays",
                "severity": "high",
                "description": f"Nouveau pays : {current_country} (précédemment : {', '.join(user_countries[:2])})"
            })
            risk_score += 20
        
        # 5. Analyse des tentatives échouées récentes
        recent_failed = 0
        recent_total = 0
        cutoff_time = current_time - timedelta(hours=24)
        
        for log in user_logs[-50:]:  # Derniers 50 logs
            try:
                log_time = datetime.fromisoformat(log['timestamp'])
                if log_time > cutoff_time:
                    recent_total += 1
                    if not log.get('success', True):
                        recent_failed += 1
            except:
                continue
        
        if recent_total > 0:
            failure_rate = (recent_failed / recent_total) * 100
            if failure_rate > 30:
                risk_factors.append({
                    "type": "taux_echec_eleve",
                    "severity": "high",
                    "description": f"Taux d'échec élevé : {failure_rate:.1f}% sur 24h"
                })
                risk_score += 30
            elif failure_rate > 15:
                risk_factors.append({
                    "type": "taux_echec_moyen",
                    "severity": "medium",
                    "description": f"Taux d'échec modéré : {failure_rate:.1f}% sur 24h"
                })
                risk_score += 15
        
        # 6. Analyse de la fréquence des connexions
        recent_connections = 0
        for log in user_logs:
            try:
                log_time = datetime.fromisoformat(log['timestamp'])
                if log_time > cutoff_time and log.get('success', True) and log.get('event_type') == 'login':
                    recent_connections += 1
            except:
                continue
        
        if recent_connections > 10:
            risk_factors.append({
                "type": "frequence_elevee",
                "severity": "medium",
                "description": f"Fréquence de connexion élevée : {recent_connections} en 24h"
            })
            risk_score += 10
        
        # Normaliser le score
        risk_score = min(100, max(0, risk_score))
        
        # Recommandation
        if risk_score >= 70:
            recommendation = "Risque élevé - Vérification supplémentaire requise"
        elif risk_score >= 40:
            recommendation = "Risque modéré - Surveillance recommandée"
        else:
            recommendation = "Risque faible - Connexion normale"
        
        return {
            "risk_score": risk_score,
            "risk_level": self._get_risk_level_from_score(risk_score),
            "factors": risk_factors,
            "recommendation": recommendation,
            "analysis_timestamp": current_time.isoformat()
        }
    
    def _get_risk_level_from_score(self, score):
        """Convertit le score numérique en niveau de risque"""
        if score >= 70:
            return "high"
        elif score >= 40:
            return "medium"
        else:
            return "low"
    
    def get_global_security_metrics(self):
        """Calcule les métriques de sécurité globales"""
        logs = self._read_json(self.auth_logs_file)
        users = self._read_json(self.users_file)
        
        if not logs:
            return {"error": "Aucun log disponible"}
        
        # Période d'analyse
        now = datetime.now()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        
        # Logs récents
        recent_logs = [log for log in logs if datetime.fromisoformat(log['timestamp']) > last_24h]
        weekly_logs = [log for log in logs if datetime.fromisoformat(log['timestamp']) > last_7d]
        
        # Métriques de base
        total_events = len(logs)
        recent_events = len(recent_logs)
        weekly_events = len(weekly_logs)
        
        # Taux de succès
        successful_logs = [log for log in logs if log.get('success', True)]
        recent_successful = [log for log in recent_logs if log.get('success', True)]
        
        success_rate = (len(successful_logs) / total_events * 100) if total_events > 0 else 0
        recent_success_rate = (len(recent_successful) / recent_events * 100) if recent_events > 0 else 0
        
        # Événements par type
        event_types = {}
        for log in logs:
            event_type = log.get('event_type', 'unknown')
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        # Niveaux de risque
        risk_levels = {}
        for log in logs:
            risk = log.get('risk_level', 'unknown')
            risk_levels[risk] = risk_levels.get(risk, 0) + 1
        
        # Métriques utilisateurs
        active_users_24h = len(set([log.get('user_id') for log in recent_logs if log.get('user_id')]))
        unique_ips_24h = len(set([log.get('ip_address') for log in recent_logs]))
        
        # Alertes de sécurité
        high_risk_events = [log for log in recent_logs if log.get('risk_level') in ['high', 'critical']]
        
        # Tendances
        if len(weekly_logs) > 1:
            # Comparaison avec la période précédente
            prev_24h = last_24h - timedelta(hours=24)
            prev_logs = [log for log in logs if prev_24h < datetime.fromisoformat(log['timestamp']) < last_24h]
            
            trend = "stable"
            if len(recent_logs) > len(prev_logs) * 1.2:
                trend = "augmentee"
            elif len(recent_logs) < len(prev_logs) * 0.8:
                trend = "diminuee"
        else:
            trend = "insuffisantes_donnees"
        
        return {
            "periode_analyse": {
                "total_events": total_events,
                "recent_24h": recent_events,
                "weekly": weekly_events
            },
            "taux_succes": {
                "global": round(success_rate, 2),
                "recent_24h": round(recent_success_rate, 2)
            },
            "activite_utilisateurs": {
                "actifs_24h": active_users_24h,
                "total_utilisateurs": len(users),
                "ips_uniques_24h": unique_ips_24h
            },
            "distribution_evenements": event_types,
            "niveaux_risque": risk_levels,
            "alertes_securite": {
                "evenements_haut_risque_24h": len(high_risk_events),
                "taux_alerte": (len(high_risk_events) / recent_events * 100) if recent_events > 0 else 0
            },
            "tendances": {
                "direction": trend,
                "variation_pct": self._calculate_trend_percentage(recent_logs, prev_logs) if 'prev_logs' in locals() else 0
            },
            "score_global_securite": self._calculate_global_security_score(recent_logs)
        }
    
    def _calculate_trend_percentage(self, current, previous):
        """Calcule le pourcentage de variation"""
        if not previous:
            return 0
        return round(((len(current) - len(previous)) / len(previous)) * 100, 2)
    
    def _calculate_global_security_score(self, logs):
        """Calcule un score de sécurité global (0-100)"""
        if not logs:
            return 50
        
        score = 100
        
        # Facteurs de pénalité
        failure_rate = len([log for log in logs if not log.get('success', True)]) / len(logs)
        high_risk_rate = len([log for log in logs if log.get('risk_level') in ['high', 'critical']]) / len(logs)
        unique_ips = len(set([log.get('ip_address') for log in logs]))
        
        # Appliquer les pénalités
        score -= failure_rate * 30  # Jusqu'à 30 points pour les échecs
        score -= high_risk_rate * 40  # Jusqu'à 40 points pour le risque élevé
        score -= min((unique_ips - 1) * 5, 20)  # Jusqu'à 20 points pour trop d'IPs
        
        return max(0, min(100, int(score)))

# Instance globale
storage = JSONStorage()

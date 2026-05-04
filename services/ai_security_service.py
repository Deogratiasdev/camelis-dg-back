import requests
import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any
import logging
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

logger = logging.getLogger(__name__)

class AISecurityService:
    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY")
        self.model = os.getenv("GROQ_MODEL", "mixtral-8x7b-32768")
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"
        
        if not self.api_key:
            logger.warning("GROQ_API_KEY non trouvé dans l'environnement")
            self.api_key = None
        else:
            logger.info(f"GROQ_API_KEY trouvé: {self.api_key[:10]}...{self.api_key[-10:]}")
            logger.info(f"Modèle: {self.model}")
    
    def _make_groq_request(self, messages: List[Dict], temperature: float = 0.1) -> str:
        """Fait une requête à l'API Groq avec requests et retourne le texte brut"""
        if not self.api_key:
            raise Exception("GROQ_API_KEY non configuré")
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # Corriger le format pour l'API Groq
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature
        }
        
        try:
            logger.info(f"Envoi requête à Groq avec modèle {self.model}")
            response = requests.post(self.base_url, headers=headers, json=payload, timeout=30)
            
            # Log de la réponse pour debug
            logger.info(f"Status code: {response.status_code}")
            if response.status_code != 200:
                logger.error(f"Réponse Groq: {response.text}")
            
            response.raise_for_status()
            
            result = response.json()
            content = result["choices"][0]["message"]["content"]
            
            # Retourner le texte brut
            return content
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Erreur requête Groq : {str(e)}")
            raise Exception(f"Erreur API Groq : {str(e)}")
        except Exception as e:
            logger.error(f"Erreur traitement réponse Groq : {str(e)}")
            raise Exception(f"Erreur traitement IA : {str(e)}")
    
    def analyze_logs_anomalies(self, logs: List[Dict], user_info: Dict = None) -> Dict[str, Any]:
        """Analyse les logs pour détecter les anomalies avec l'IA (personnalisée)"""
        if not self.api_key:
            return self._fallback_anomaly_analysis(logs, user_info)
        
        try:
            # Préparer les logs pour l'IA
            logs_summary = self._prepare_logs_for_ai(logs)
            
            # Ajouter les informations utilisateur si disponibles
            user_context = ""
            if user_info:
                user_context = f"""
INFORMATIONS UTILISATEUR:
- Nom: {user_info.get('first_name', 'N/A')} {user_info.get('last_name', 'N/A')}
- Email: {user_info.get('email', 'N/A')}
- Statut: {'Vérifié' if user_info.get('is_verified', False) else 'Non vérifié'}
- Date d'inscription: {user_info.get('created_at', 'N/A')}
"""
            
            # Prompt système personnalisé pour détection d'anomalies
            system_prompt = f"""Tu es un expert en cybersécurité bancaire. Analyse ces logs d'authentification pour l'utilisateur spécifié et identifie :
1. Les tentatives suspectes (brute-force, accès inhabituels)
2. Les patterns de comportement anormaux  
3. Les failles potentielles exploitées
4. Les recommandations PERSONNALISÉES et ACTIONNABLES

{user_context}

IMPORTANT: Tu dois répondre en texte naturel, en quelques phrases claires et concises. Pas de JSON, pas de markdown, uniquement du texte en français.

Structure ta réponse ainsi :
- Résumé de la situation (1-2 phrases)
- Anomalies détectées (1-3 phrases)
- Recommandations (1-3 phrases)"""

            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Logs à analyser :\n{logs_summary}"}
            ]
            
            result = self._make_groq_request(messages, temperature=0.1)
            logger.info(f"Analyse IA personnalisée terminée")
            return result
            
        except Exception as e:
            logger.error(f"Erreur analyse IA logs : {str(e)}")
            return self._fallback_anomaly_analysis(logs, user_info)
    
    def _fallback_anomaly_analysis(self, logs: List[Dict], user_info: Dict = None) -> Dict[str, Any]:
        """Analyse de secours sans IA (personnalisée)"""
        try:
            alertes = []
            score_risque = 0
            recommandations = []
            
            # Analyser les logs sans IA
            failed_attempts = [log for log in logs if not log.get('success', True)]
            unique_ips = len(set([log.get('ip_address', '') for log in logs]))
            successful_attempts = [log for log in logs if log.get('success', True)]
            
            # Informations utilisateur pour personnalisation
            user_name = f"{user_info.get('first_name', '')} {user_info.get('last_name', '')}".strip() if user_info else "Utilisateur"
            user_email = user_info.get('email', '') if user_info else ''
            
            # Détection basique d'anomalies avec recommandations personnalisées
            if len(failed_attempts) > len(logs) * 0.3:  # Plus de 30% d'échecs
                alertes.append({
                    "type": "taux_echec_eleve",
                    "niveau_risque": "eleve",
                    "description": f"{user_name} : Taux d'échec élevé de {len(failed_attempts)}/{len(logs)} tentatives",
                    "evidences": [f"{len(failed_attempts)} tentatives échouées"],
                    "recommandation_personnalisee": f"{user_name} devrait vérifier ses identifiants et activer l'authentification à deux facteurs",
                    "impact_potentiel": "Risque de compromission du compte de l'utilisateur"
                })
                score_risque += 40
                recommandations.append({
                    "titre": f"Renforcer la sécurité du compte de {user_name}",
                    "priorite": "elevee",
                    "description": f"Le compte de {user_name} montre un taux d'échec anormal",
                    "exemples_concrets": [
                        "Changer le mot de passe actuel pour un mot de passe plus complexe (12+ caractères, majuscules, chiffres, symboles)",
                        "Activer la vérification en deux étapes si ce n'est pas déjà fait",
                        "Vérifier les appareils connectés et supprimer ceux qui ne sont pas reconnus"
                    ],
                    "delai_mise_en_oeuvre": "24h",
                    "effort_requis": "moyen"
                })
            
            if unique_ips > 5:
                alertes.append({
                    "type": "multiples_ips",
                    "niveau_risque": "moyen",
                    "description": f"{user_name} : Connexions depuis {unique_ips} adresses IP différentes",
                    "evidences": [f"{unique_ips} IPs uniques détectées"],
                    "recommandation_personnalisee": f"{user_name} devrait vérifier si toutes ces connexions sont légitimes",
                    "impact_potentiel": "Possibilité d'accès non autorisé au compte"
                })
                score_risque += 20
                recommandations.append({
                    "titre": f"Sécuriser les connexions de {user_name}",
                    "priorite": "moyenne",
                    "description": f"Plusieurs adresses IP utilisées pour le compte de {user_name}",
                    "exemples_concrets": [
                        "Examiner l'historique des connexions et identifier les appareils inconnus",
                        "Utiliser un VPN si les connexions multiples sont légitimes mais géographiquement dispersées",
                        "Activer les alertes de connexion par email pour chaque nouvelle adresse IP"
                    ],
                    "delai_mise_en_oeuvre": "immédiat",
                    "effort_requis": "faible"
                })
            
            # Détecter les IPs avec beaucoup d'échecs
            ip_failures = {}
            for log in failed_attempts:
                ip = log.get('ip_address', '')
                ip_failures[ip] = ip_failures.get(ip, 0) + 1
            
            for ip, count in ip_failures.items():
                if count > 3:
                    alertes.append({
                        "type": "brute_force",
                        "niveau_risque": "eleve",
                        "description": f"{user_name} : Tentatives de brute-force depuis l'IP {ip}",
                        "evidences": [f"{count} échecs depuis {ip}"],
                        "recommandation_personnalisee": f"{user_name} doit bloquer cette IP et renforcer son mot de passe",
                        "impact_potentiel": "Tentative active de compromission du compte"
                    })
                    score_risque += 30
                    recommandations.append({
                        "titre": f"Protection contre brute-force pour {user_name}",
                        "priorite": "critique",
                        "description": f"Attaque brute-force détectée contre le compte de {user_name}",
                        "exemples_concrets": [
                            "Bloquer temporairement l'adresse IP {ip}",
                            "Changer immédiatement le mot de passe pour un mot de passe plus robuste",
                            "Activer la protection contre les tentatives de connexion répétées"
                        ],
                        "delai_mise_en_oeuvre": "immédiat",
                        "effort_requis": "faible"
                    })
            
            # Ajouter des recommandations générales si aucune alerte
            if not alertes:
                recommandations.append({
                    "titre": f"Maintenir la bonne sécurité du compte de {user_name}",
                    "priorite": "faible",
                    "description": f"Le compte de {user_name} présente un bon niveau de sécurité",
                    "exemples_concrets": [
                        "Continuer à utiliser des mots de passe robustes et uniques",
                        "Mettre à jour régulièrement les informations de récupération",
                        "Vérifier périodiquement les appareils connectés"
                    ],
                    "delai_mise_en_oeuvre": "1semaine",
                    "effort_requis": "faible"
                })
            
            return {
                "alertes": alertes,
                "score_global_risque": min(100, score_risque),
                "tendance": "stable",
                "recommandations_personnalisees": recommandations,
                "resume_utilisateur": f"{user_name} présente {'un risque élevé' if score_risque > 60 else 'un risque modéré' if score_risque > 30 else 'un faible risque'} avec {len(alertes)} alerte(s) détectée(s)",
                "mode": "fallback_sans_ia"
            }
            
        except Exception as e:
            logger.error(f"Erreur analyse fallback : {str(e)}")
            return {
                "alertes": [],
                "score_global_risque": 0,
                "tendance": "stable",
                "recommandations_personnalisees": [],
                "resume_utilisateur": "Erreur lors de l'analyse",
                "mode": "fallback_sans_ia",
                "erreur": f"Erreur analyse : {str(e)}"
            }
    
    def predict_threats(self, historical_logs: List[Dict]) -> Dict[str, Any]:
        """Prédit les menaces émergentes basées sur l'historique"""
        if not self.api_key:
            return self._fallback_threat_prediction(historical_logs)
        
        try:
            # Analyser les tendances sur 7 jours
            trends = self._analyze_trends(historical_logs)
            
            system_prompt = """Tu es un analyste en threat intelligence. Sur la base des tendances historiques :
1. Identifie les menaces émergentes probables
2. Prédis les prochains vecteurs d'attaque
3. Propose des règles de prévention proactives

IMPORTANT: Tu dois répondre en texte naturel, en quelques phrases claires et concises. Pas de JSON, pas de markdown, uniquement du texte en français.

Structure ta réponse ainsi :
- Menaces émergentes (1-2 phrases)
- Vecteurs d'attaque probables (1-2 phrases)
- Règles de prévention (1-2 phrases)"""

            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Tendances analysées :\n{json.dumps(trends, indent=2)}"}
            ]
            
            result = self._make_groq_request(messages, temperature=0.2)
            return result
            
        except Exception as e:
            logger.error(f"Erreur prédiction menaces : {str(e)}")
            return self._fallback_threat_prediction(historical_logs)
    
    def _fallback_threat_prediction(self, historical_logs: List[Dict]) -> Dict[str, Any]:
        """Prédiction de secours sans IA"""
        try:
            menaces = []
            regles = []
            
            # Analyser les tendances basiques
            if len(historical_logs) < 10:
                menaces.append({
                    "type": "manque_donnees",
                    "probabilite": "50",
                    "periode": "court_terme",
                    "description": "Volume insuffisant de logs pour analyse prédictive",
                    "indicateurs": ["Moins de 10 événements"],
                    "mitigation": "Augmenter la collecte de logs"
                })
            else:
                # Détecter les tendances basiques
                recent_logs = historical_logs[-10:]  # 10 derniers logs
                failed_recent = len([log for log in recent_logs if not log.get('success', True)])
                
                if failed_recent > 5:
                    menaces.append({
                        "type": "augmentation_tentatives",
                        "probabilite": "70",
                        "periode": "immediate",
                        "description": "Augmentation des tentatives échouées récentes",
                        "indicateurs": [f"{failed_recent}/10 échecs récents"],
                        "mitigation": "Renforcer rate limiting"
                    })
                    regles.append({
                        "regle": "Limiter tentatives par IP",
                        "priorite": "elevee",
                        "impact_estime": "60%"
                    })
            
            return {
                "menaces_emergentes": menaces,
                "regles_prevention": regles,
                "score_maturite_securite": 50,
                "mode": "fallback_sans_ia"
            }
            
        except Exception as e:
            logger.error(f"Erreur prédiction fallback : {str(e)}")
            return {
                "menaces_emergentes": [],
                "regles_prevention": [],
                "score_maturite_securite": 50,
                "erreur": f"Erreur prédiction : {str(e)}"
            }
    
    def generate_security_recommendations(self, security_metrics: Dict) -> Dict[str, Any]:
        """Génère des recommandations de sécurité personnalisées"""
        if not self.api_key:
            return self._fallback_recommendations(security_metrics)
        
        try:
            system_prompt = """Tu es architecte sécurité. Analyse les métriques et suggère 3-5 améliorations concrètes avec ROI sécurité/UX.

IMPORTANT: Tu dois répondre en texte naturel, en quelques phrases claires et concises. Pas de JSON, pas de markdown, uniquement du texte en français.

Structure ta réponse ainsi :
- Recommandations principales (2-3 phrases)
- Priorités d'action (1-2 phrases)
- Impact attendu (1-2 phrases)"""

            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Métriques de sécurité :\n{json.dumps(security_metrics, indent=2)}"}
            ]
            
            result = self._make_groq_request(messages, temperature=0.3)
            return result
            
        except Exception as e:
            logger.error(f"Erreur recommandations IA : {str(e)}")
            return self._fallback_recommendations(security_metrics)
    
    def _fallback_recommendations(self, security_metrics: Dict) -> Dict[str, Any]:
        """Recommandations de secours sans IA"""
        try:
            recommandations = []
            
            # Analyser les métriques basiques
            score_global = security_metrics.get('score_global_securite', 50)
            taux_succes = security_metrics.get('taux_succes', {}).get('recent_24h', 100)
            alertes = security_metrics.get('alertes_securite', {}).get('evenements_haut_risque_24h', 0)
            
            if score_global < 70:
                recommandations.append({
                    "titre": "Améliorer le score de sécurité global",
                    "priorite": "elevee",
                    "effort_implementation": "moyen",
                    "impact_securite": 80,
                    "impact_ux": "neutral",
                    "description": f"Le score de sécurité est de {score_global}/100, amélioration nécessaire",
                    "etapes": ["Analyser les logs", "Renforcer l'authentification", "Surveiller les alertes"],
                    "delai_estime": "3 jours",
                    "roi": "Réduction significative des risques"
                })
            
            if taux_succes < 90:
                recommandations.append({
                    "titre": "Réduire le taux d'échec d'authentification",
                    "priorite": "moyenne",
                    "effort_implementation": "faible",
                    "impact_securite": 60,
                    "impact_ux": "positif",
                    "description": f"Taux de succès de {taux_succes}% - optimiser l'expérience utilisateur",
                    "etapes": ["Simplifier le processus", "Améliorer les messages d'erreur", "Ajouter de l'aide"],
                    "delai_estime": "1 jour",
                    "roi": "Meilleure expérience utilisateur"
                })
            
            if alertes > 5:
                recommandations.append({
                    "titre": "Gérer les alertes de sécurité actives",
                    "priorite": "critique",
                    "effort_implementation": "faible",
                    "impact_securite": 90,
                    "impact_ux": "neutral",
                    "description": f"{alertes} alertes de haute priorité nécessitent une attention immédiate",
                    "etapes": ["Examiner chaque alerte", "Bloquer les menaces", "Documenter les actions"],
                    "delai_estime": "2 heures",
                    "roi": "Prévention des incidents"
                })
            
            return {
                "recommandations": recommandations,
                "score_amelioration_potentiel": min(100, len(recommandations) * 20),
                "mode": "fallback_sans_ia"
            }
            
        except Exception as e:
            logger.error(f"Erreur recommandations fallback : {str(e)}")
            return {
                "recommandations": [],
                "score_amelioration_potentiel": 0,
                "erreur": f"Erreur recommandations : {str(e)}"
            }
    
    def _prepare_logs_for_ai(self, logs: List[Dict]) -> str:
        """Prépare les logs pour l'analyse IA"""
        if not logs:
            return "Aucun log à analyser"
        
        # Limiter aux 50 logs les plus récents pour éviter le token limit
        recent_logs = sorted(logs, key=lambda x: x.get('timestamp', ''), reverse=True)[:50]
        
        logs_text = []
        for log in recent_logs:
            log_entry = {
                "timestamp": log.get('timestamp', ''),
                "event_type": log.get('event_type', ''),
                "success": log.get('success', False),
                "risk_level": log.get('risk_level', 'unknown'),
                "ip_address": log.get('ip_address', ''),
                "country": log.get('country', ''),
                "details": log.get('details', ''),
                "device": log.get('device', {}),
                "user_id": log.get('user_id', '')
            }
            logs_text.append(json.dumps(log_entry, separators=(',', ':')))
        
        return '\n'.join(logs_text)
    
    def _analyze_trends(self, logs: List[Dict]) -> Dict[str, Any]:
        """Analyse les tendances dans les logs historiques"""
        if not logs:
            return {}
        
        # Statistiques de base
        total_logs = len(logs)
        failed_attempts = len([log for log in logs if not log.get('success', True)])
        unique_ips = len(set([log.get('ip_address', '') for log in logs]))
        unique_users = len(set([log.get('user_id', '') for log in logs]))
        
        # Tendances par jour
        daily_stats = {}
        for log in logs:
            date = log.get('timestamp', '')[:10]  # YYYY-MM-DD
            if date not in daily_stats:
                daily_stats[date] = {"total": 0, "failed": 0, "unique_ips": set()}
            daily_stats[date]["total"] += 1
            if not log.get('success', True):
                daily_stats[date]["failed"] += 1
            daily_stats[date]["unique_ips"].add(log.get('ip_address', ''))
        
        # Convertir les sets en count
        for date in daily_stats:
            daily_stats[date]["unique_ips"] = len(daily_stats[date]["unique_ips"])
        
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
        
        return {
            "periode_analyse": f"{len(daily_stats)} jours",
            "statistiques_globales": {
                "total_logs": total_logs,
                "taux_echec": round((failed_attempts / total_logs) * 100, 2) if total_logs > 0 else 0,
                "ips_uniques": unique_ips,
                "utilisateurs_uniques": unique_users
            },
            "tendances_journalieres": daily_stats,
            "types_evenements": event_types,
            "niveaux_risque": risk_levels
        }

# Instance globale
ai_security_service = AISecurityService()

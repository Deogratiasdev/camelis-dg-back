"""
Service d'envoi d'emails via Brevo (Sendinblue)
"""
import os
import requests
from typing import Optional
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()


class EmailService:
    """Service d'envoi d'emails via API Brevo"""
    
    def __init__(self):
        self.api_key = os.getenv("BREVO_API_KEY")
        self.sender_email = os.getenv("BREVO_SENDER_EMAIL", "deogratiashounnou1@gmail.com")
        self.sender_name = os.getenv("BREVO_SENDER_NAME", "Security web")
        self.base_url = "https://api.brevo.com/v3"
        
    def send_otp_email(self, to_email: str, otp_code: str, first_name: Optional[str] = None) -> bool:
        """
        Envoie un email OTP via Brevo
        """
        if not self.api_key:
            print("[EMAIL] BREVO_API_KEY non configurée")
            return False
            
        name = first_name or "Utilisateur"
        
        text_content = f"""SecureAuth - Verification de securite

Bonjour {name},

Voici votre code de verification pour securiser votre compte :

    {otp_code}

Ce code est valable pendant 10 minutes.

Si vous n'avez pas demande ce code, ignorez cet email.
Ne partagez jamais ce code avec qui que ce soit.

---
Security web"""
        
        payload = {
            "sender": {
                "name": self.sender_name,
                "email": self.sender_email
            },
            "to": [{"email": to_email}],
            "subject": "Votre code de verification SecureAuth",
            "textContent": text_content
        }
        
        headers = {
            "accept": "application/json",
            "api-key": self.api_key,
            "content-type": "application/json"
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/smtp/email",
                json=payload,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 201:
                print(f"[EMAIL] OTP envoyé avec succès à {to_email}")
                return True
            else:
                print(f"[EMAIL] Erreur Brevo: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            print(f"[EMAIL] Erreur envoi: {str(e)}")
            return False
    
    def send_welcome_email(self, to_email: str, first_name: Optional[str] = None) -> bool:
        """Envoie un email de bienvenue"""
        if not self.api_key:
            return False
            
        name = first_name or "Utilisateur"
        
        text_content = f"""SecureAuth - Bienvenue !

Bonjour {name},

Votre compte est maintenant securise avec notre systeme d'authentification multi-facteurs.

Fonctionnalites :
- Authentification 4 facteurs
- Reconnaissance vocale
- Surveillance IA 24/7

Protegez ce qui compte vraiment.

---
Security web"""
        
        payload = {
            "sender": {
                "name": self.sender_name,
                "email": self.sender_email
            },
            "to": [{"email": to_email}],
            "subject": "Bienvenue sur SecureAuth",
            "textContent": text_content
        }
        
        headers = {
            "accept": "application/json",
            "api-key": self.api_key,
            "content-type": "application/json"
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/smtp/email",
                json=payload,
                headers=headers,
                timeout=10
            )
            return response.status_code == 201
        except Exception as e:
            print(f"[EMAIL] Erreur envoi welcome: {str(e)}")
            return False


# Instance singleton
email_service = EmailService()

#!/usr/bin/env python3
"""Test envoi email Brevo"""
import os
from dotenv import load_dotenv

# Charger .env
load_dotenv()

print(f"BREVO_API_KEY: {os.getenv('BREVO_API_KEY', 'NON TROUVE')[:20]}...")
print(f"BREVO_SENDER_EMAIL: {os.getenv('BREVO_SENDER_EMAIL', 'NON TROUVE')}")
print(f"BREVO_SENDER_NAME: {os.getenv('BREVO_SENDER_NAME', 'NON TROUVE')}")

from services.email_service import email_service

# Test envoi
result = email_service.send_otp_email(
    to_email="deogratiashounnou1@gmail.com",
    otp_code="123456",
    first_name="Test"
)

print(f"\nResultat envoi: {'SUCCES' if result else 'ECHEC'}")

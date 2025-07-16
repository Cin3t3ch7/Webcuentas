import os
from dotenv import load_dotenv

load_dotenv()

# Telegram Bot - NUEVO TOKEN
BOT_TOKEN = "7562094195:AAE1MiPYhX9aaKnUv012V9I5Qq6ARH0AE9o"

# Super Admins - AHORA ES UNA LISTA
SUPER_ADMIN_IDS = [1048035220]

# PostgreSQL Database - CONFIGURACIÓN PARA VPS
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://disney_user:Disney2024Pro!@localhost/disney_search_db")

# Web Security
SECRET_KEY = os.getenv("SECRET_KEY", "disney-search-pro-secret-key-2025-vps-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Disney Regex Patterns - Patrones mejorados y más específicos
DISNEY_PATTERNS = {
    'disney_code': r'<td[^>]*>\s*(\d{4,8})\s*</td>',  # Códigos de 4-8 dígitos en tabla
    'disney_household': r'(?:Household|household)[\s\S]*?<td[^>]*>\s*(\d{6,8})\s*</td>',  # Household codes
    'disney_mydisney': r'(?:otp_code|verification[_\s]code)[^>]*>\s*(\d{4,8})\s*<',  # OTP codes
    'disney_general': r'(?:código|code|verification)[\s:]*(\d{4,8})',  # Códigos generales
    'disney_plain': r'\b(\d{6})\b'  # Códigos de 6 dígitos simples
}

# Direcciones de email de Disney
DISNEY_FROM_ADDRESSES = [
    'disneyplus@trx.mail2.disneyplus.com',
    'member.services@disneyaccount.com'
]

# Configuración del sistema de verificación
VERIFICATION_DELAY_SECONDS = 40  # Tiempo de espera antes de verificar cambios
MAX_VERIFICATION_THREADS = 50   # Máximo número de threads de verificación simultáneos

# Configuración de reconexión
MAX_DB_RETRIES = 5
DB_RETRY_DELAY = 2
MAX_IMAP_RETRIES = 3
IMAP_RETRY_DELAY = 2

# Configuración de timeouts
IMAP_TIMEOUT = 30
WEB_TIMEOUT = 30
BOT_TIMEOUT = 30

# Configuración de logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Configuración para producción
PRODUCTION = os.getenv("PRODUCTION", "true").lower() == "true"
HOST = "0.0.0.0" if PRODUCTION else "127.0.0.1"
PORT = int(os.getenv("PORT", "8000"))

# Función helper para verificar si un usuario es super admin
def is_super_admin(user_id):
    """Verifica si un usuario es super admin"""
    return user_id in SUPER_ADMIN_IDS

# Función para obtener el primer super admin (para compatibilidad)
def get_primary_super_admin():
    """Obtiene el primer super admin de la lista"""
    return SUPER_ADMIN_IDS[0] if SUPER_ADMIN_IDS else None
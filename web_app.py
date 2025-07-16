import os
import secrets
import hashlib
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Form, HTTPException, Depends, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext
from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, SUPER_ADMIN_IDS, is_super_admin
from database import db
from disney_search import disney_searcher
import logging

logger = logging.getLogger(__name__)

# Configuración de FastAPI
app = FastAPI(title="Disney Search Pro", description="Sistema de búsqueda de códigos Disney")

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Archivos estáticos y templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Seguridad
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

class AuthManager:
    @staticmethod
    def create_access_token(user_id: int):
        """Crea token de acceso JWT"""
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode = {
            "sub": str(user_id),
            "exp": expire,
            "iat": datetime.utcnow()
        }
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    @staticmethod
    def verify_token(token: str):
        """Verifica y decodifica token JWT"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id = int(payload.get("sub"))
            return user_id
        except JWTError:
            return None
    
    @staticmethod
    def create_csrf_token():
        """Crea token CSRF"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def verify_csrf_token(session_token: str, csrf_token: str):
        """Verifica token CSRF"""
        try:
            session_data = db.execute_query(
                "SELECT csrf_token FROM web_sessions WHERE session_token = %s AND is_active = TRUE",
                (session_token,)
            )
            return session_data and session_data[0]['csrf_token'] == csrf_token
        except Exception as e:
            logger.error(f"Error verificando CSRF token: {e}")
            return False

async def get_current_user(request: Request):
    """Obtiene el usuario actual de la sesión con verificaciones mejoradas"""
    session_token = request.cookies.get("session_token")
    
    if not session_token:
        return None

    try:
        session_data = db.execute_query("""
            SELECT s.user_id, s.expires_at, s.csrf_token,
                   u.username, u.first_name, u.is_admin, u.free_access, 
                   u.is_blocked, u.blocked_reason, u.blocked_at
            FROM web_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = %s AND s.is_active = TRUE
        """, (session_token,))
        
        if not session_data:
            return None
        
        session = session_data[0]
        
        # Verificar si está bloqueado y cerrar sesión automáticamente
        if session['is_blocked']:
            logger.warning(f"Usuario bloqueado detectado en sesión activa: {session['user_id']}")
            
            # Invalidar la sesión automáticamente
            try:
                db.execute_query(
                    "UPDATE web_sessions SET is_active = FALSE WHERE session_token = %s",
                    (session_token,)
                )
                logger.info(f"🔒 Sesión invalidada automáticamente para usuario bloqueado: {session['user_id']}")
            except Exception as e:
                logger.error(f"Error invalidando sesión de usuario bloqueado: {e}")
            
            return None
        
        # Verificar expiración
        if datetime.now() > session['expires_at']:
            db.execute_query(
                "UPDATE web_sessions SET is_active = FALSE WHERE session_token = %s",
                (session_token,)
            )
            return None
        
        return {
            'id': session['user_id'],
            'telegramId': session['user_id'],
            'username': session['username'],
            'firstName': session['first_name'],
            'isAdmin': session['is_admin'],
            'isSuperAdmin': is_super_admin(session['user_id']),
            'free_access': session['free_access'],
            'is_blocked': session['is_blocked'],
            'csrf_token': session['csrf_token']
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo usuario actual: {e}")
        return None

async def require_auth(request: Request):
    """Requiere autenticación con verificación de estado mejorada"""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="No autenticado")
    
    if user.get('is_blocked'):
        raise HTTPException(status_code=403, detail="Usuario bloqueado")
    
    return user

def can_use_email_web_restricted(user_info, email: str) -> bool:
    """✅ CORREGIDO: Verifica si el usuario puede usar un email específico en la web (VERSIÓN CASE-INSENSITIVE)"""
    user_id = user_info['id']
    
    # Super admins tienen acceso a todos los emails
    if user_info.get('isSuperAdmin', False):
        return True
    
    # Admins normales: SOLO emails asignados específicamente (comparación case-insensitive)
    if user_info.get('isAdmin', False):
        try:
            # ✅ CORRECCIÓN: Usar LOWER() en SQL para comparación case-insensitive
            assigned_email = db.execute_query(
                "SELECT id FROM user_emails WHERE user_id = %s AND LOWER(email) = LOWER(%s)",
                (user_id, email)
            )
            return bool(assigned_email)
        except Exception as e:
            logger.error(f"Error verificando email asignado para admin: {e}")
            return False
    
    # Usuarios normales: verificar acceso libre o email asignado
    if user_info.get('free_access', False):
        return True
    
    try:
        # ✅ CORRECCIÓN: Usar LOWER() en SQL para comparación case-insensitive
        assigned_email = db.execute_query(
            "SELECT id FROM user_emails WHERE user_id = %s AND LOWER(email) = LOWER(%s)",
            (user_id, email)
        )
        return bool(assigned_email)
    except Exception as e:
        logger.error(f"Error verificando email asignado: {e}")
        return False

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Dashboard principal con restricciones para admins"""
    user = await get_current_user(request)
    
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    
    if user.get('is_blocked'):
        return RedirectResponse(url="/login", status_code=302)
    
    try:
        # Obtener emails del usuario según su tipo
        emails = []
        
        # Super admins: no muestran emails específicos (pueden usar cualquiera)
        if user.get('isSuperAdmin', False):
            emails = []
        # Admins normales y usuarios: solo emails asignados
        elif user.get('isAdmin', False) or not user.get('free_access', False):
            email_data = db.execute_query(
                "SELECT email FROM user_emails WHERE user_id = %s ORDER BY email",
                (user['id'],)
            )
            emails = [row['email'] for row in email_data] if email_data else []
        # Usuarios con acceso libre: no muestran emails específicos
        else:
            emails = []
        
        # Obtener estadísticas
        total_searches = db.execute_query(
            "SELECT COUNT(*) as count FROM disney_searches WHERE user_id = %s",
            (user['id'],)
        )
        
        search_count = total_searches[0]['count'] if total_searches else 0
        
        return templates.TemplateResponse("index.html", {
            "request": request,
            "user": user,
            "emails": emails,
            "search_count": search_count
        })
        
    except Exception as e:
        logger.error(f"Error cargando dashboard: {e}")
        return RedirectResponse(url="/login", status_code=302)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Página de login con redirección inteligente"""
    user = await get_current_user(request)
    if user and not user.get('is_blocked'):
        return RedirectResponse(url="/", status_code=302)
    
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/api/login")
async def login_api(request: Request):
    """API de login con validación mejorada"""
    try:
        data = await request.json()
        telegram_id_str = data.get('telegramId', '').strip()
        
        if not telegram_id_str:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "ID de Telegram requerido"}
            )
        
        try:
            user_id = int(telegram_id_str)
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "ID de Telegram inválido"}
            )
        
        # Verificar si el usuario existe y está activo
        user_data = db.execute_query("""
            SELECT id, username, first_name, is_admin, free_access, expires_at, is_active, is_blocked, blocked_reason
            FROM users WHERE id = %s
        """, (user_id,))
        
        if not user_data:
            return JSONResponse(
                status_code=401,
                content={"success": False, "error": "Usuario no autorizado"}
            )
        
        user = user_data[0]
        
        if user['is_blocked']:
            reason = user['blocked_reason'] or "Usuario bloqueado"
            return JSONResponse(
                status_code=403,
                content={"success": False, "error": f"Cuenta bloqueada: {reason}"}
            )
        
        if not user['is_active']:
            return JSONResponse(
                status_code=401,
                content={"success": False, "error": "Cuenta desactivada"}
            )
        
        if user['expires_at'] and datetime.now() > user['expires_at']:
            return JSONResponse(
                status_code=401,
                content={"success": False, "error": "Acceso expirado"}
            )
        
        # Crear sesión
        session_token = secrets.token_urlsafe(32)
        csrf_token = AuthManager.create_csrf_token()
        expires_at = datetime.now() + timedelta(hours=24)
        
        # Invalidar sesiones anteriores del mismo usuario (opcional - para seguridad)
        db.execute_query("""
            UPDATE web_sessions 
            SET is_active = FALSE 
            WHERE user_id = %s AND is_active = TRUE
        """, (user_id,))
        
        # Crear nueva sesión
        db.execute_query("""
            INSERT INTO web_sessions (user_id, session_token, csrf_token, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (user_id, session_token, csrf_token, expires_at))
        
        # Crear respuesta con cookie
        response = JSONResponse(content={
            "success": True,
            "user": {
                "id": user['id'],
                "telegramId": user['id'],
                "username": user['username'],
                "firstName": user['first_name']
            }
        })
        
        response.set_cookie(
            key="session_token",
            value=session_token,
            max_age=86400,
            httponly=True,
            secure=False,
            samesite="lax"
        )
        
        logger.info(f"✅ Login exitoso para usuario {user_id}")
        return response
        
    except Exception as e:
        logger.error(f"Error en login: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": "Error interno del servidor"}
        )

@app.get("/api/csrf-token")
async def get_csrf_token(request: Request):
    """Obtiene token CSRF con manejo mejorado"""
    session_token = request.cookies.get("session_token")
    
    if not session_token:
        csrf_token = AuthManager.create_csrf_token()
        return JSONResponse(content={"csrfToken": csrf_token})
    
    try:
        session_data = db.execute_query(
            "SELECT csrf_token FROM web_sessions WHERE session_token = %s AND is_active = TRUE",
            (session_token,)
        )
        
        if session_data:
            return JSONResponse(content={"csrfToken": session_data[0]['csrf_token']})
        else:
            csrf_token = AuthManager.create_csrf_token()
            return JSONResponse(content={"csrfToken": csrf_token})
            
    except Exception as e:
        logger.error(f"Error obteniendo CSRF token: {e}")
        csrf_token = AuthManager.create_csrf_token()
        return JSONResponse(content={"csrfToken": csrf_token})

@app.get("/api/auth/check")
async def check_auth(user = Depends(require_auth)):
    """Verifica autenticación"""
    return JSONResponse(content={
        "success": True,
        "user": user
    })

@app.get("/api/user/status")
async def check_user_status(request: Request):
    """Verifica específicamente el estado del usuario (bloqueado, activo, etc.)"""
    session_token = request.cookies.get("session_token")
    
    if not session_token:
        return JSONResponse(
            status_code=401,
            content={"success": False, "error": "No hay sesión activa"}
        )
    
    try:
        session_data = db.execute_query("""
            SELECT s.user_id, s.expires_at, u.is_blocked, u.blocked_reason, u.blocked_at
            FROM web_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = %s AND s.is_active = TRUE
        """, (session_token,))
        
        if not session_data:
            return JSONResponse(
                status_code=401,
                content={"success": False, "error": "Sesión inválida"}
            )
        
        session = session_data[0]
        
        # Si está bloqueado, invalidar la sesión y devolver información del bloqueo
        if session['is_blocked']:
            # Invalidar la sesión automáticamente
            db.execute_query(
                "UPDATE web_sessions SET is_active = FALSE WHERE session_token = %s",
                (session_token,)
            )
            
            return JSONResponse(content={
                "success": False,
                "blocked": True,
                "blocked_reason": session['blocked_reason'],
                "blocked_at": session['blocked_at'].isoformat() if session['blocked_at'] else None,
                "message": f"Usuario bloqueado: {session['blocked_reason'] or 'Sin razón especificada'}"
            })
        
        # Verificar expiración
        if datetime.now() > session['expires_at']:
            db.execute_query(
                "UPDATE web_sessions SET is_active = FALSE WHERE session_token = %s",
                (session_token,)
            )
            return JSONResponse(
                status_code=401,
                content={"success": False, "error": "Sesión expirada"}
            )
        
        return JSONResponse(content={
            "success": True,
            "blocked": False,
            "active": True
        })
        
    except Exception as e:
        logger.error(f"Error verificando estado del usuario: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": "Error interno del servidor"}
        )

@app.post("/api/auth/logout")
async def logout(request: Request):
    """Logout con limpieza mejorada"""
    session_token = request.cookies.get("session_token")
    
    if session_token:
        try:
            result = db.execute_query(
                "UPDATE web_sessions SET is_active = FALSE WHERE session_token = %s",
                (session_token,)
            )
            if result > 0:
                logger.info("✅ Sesión cerrada correctamente")
        except Exception as e:
            logger.error(f"Error en logout: {e}")
    
    response = JSONResponse(content={"success": True})
    response.delete_cookie(key="session_token")
    return response

@app.get("/api/user/emails")
async def get_user_emails(user = Depends(require_auth)):
    """Obtiene emails del usuario con restricciones estrictas para admins"""
    try:
        # Super admins: comportamiento original (sin emails específicos, pueden usar cualquiera)
        if user.get('isSuperAdmin', False):
            return JSONResponse(content={
                "emails": [],
                "access_type": "super_admin",
                "message": "Acceso total a todos los emails"
            })
        
        # Admins normales: SOLO emails asignados específicamente
        if user.get('isAdmin', False):
            email_data = db.execute_query(
                "SELECT email FROM user_emails WHERE user_id = %s ORDER BY email",
                (user['id'],)
            )
            emails = [row['email'] for row in email_data] if email_data else []
            return JSONResponse(content={
                "emails": emails,
                "access_type": "admin_restricted",
                "message": f"Solo puedes usar {len(emails)} emails asignados específicamente"
            })
        
        # Usuarios con acceso libre
        if user.get('free_access', False):
            return JSONResponse(content={
                "emails": [],
                "access_type": "free_access",
                "message": "Acceso libre a todos los emails"
            })
        
        # Usuarios normales: solo emails asignados
        email_data = db.execute_query(
            "SELECT email FROM user_emails WHERE user_id = %s ORDER BY email",
            (user['id'],)
        )
        emails = [row['email'] for row in email_data] if email_data else []
        return JSONResponse(content={
            "emails": emails,
            "access_type": "user_restricted",
            "message": f"Tienes acceso a {len(emails)} emails asignados"
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo emails: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Error obteniendo emails"}
        )

@app.post("/api/search-disney")
async def search_disney_api(
    request: Request,
    user = Depends(require_auth)
):
    """✅ CORREGIDO: API de búsqueda Disney con verificaciones case-insensitive para admins"""
    try:
        data = await request.json()
        email = data.get('email', '').strip()
        csrf_token = data.get('csrfToken', '')
        
        # Verificar CSRF
        session_token = request.cookies.get("session_token")
        if not AuthManager.verify_csrf_token(session_token, csrf_token):
            return JSONResponse(
                status_code=403,
                content={"error": "Token CSRF inválido"}
            )
        
        # Validar email
        if not email or '@' not in email:
            return JSONResponse(
                status_code=400,
                content={"error": "Email inválido"}
            )
        
        # Validación adicional de formato de email
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return JSONResponse(
                status_code=400,
                content={"error": "Formato de email inválido"}
            )
        
        # ✅ CORRECCIÓN: Usar la nueva función case-insensitive
        if not can_use_email_web_restricted(user, email):
            # Mensaje diferenciado según el tipo de usuario
            if user.get('isSuperAdmin', False):
                error_msg = "Error inesperado de permisos para super administrador"
            elif user.get('isAdmin', False):
                error_msg = "Como administrador, solo puedes usar emails específicamente asignados a tu cuenta"
            elif user.get('free_access', False):
                error_msg = "Error inesperado de permisos para usuario con acceso libre"
            else:
                error_msg = "Solo puedes usar emails asignados a tu cuenta"
            
            # ✅ Log de depuración para case sensitivity
            logger.warning(f"🚫 Permiso denegado para {user['id']} usando email: {email}")
            logger.warning(f"   Tipo usuario: {'super_admin' if user.get('isSuperAdmin') else 'admin' if user.get('isAdmin') else 'user'}")
            
            return JSONResponse(
                status_code=403,
                content={"error": f"❌ Sin permisos: {error_msg}"}
            )
        
        # Log específico para admins
        if user.get('isAdmin', False) and not user.get('isSuperAdmin', False):
            logger.info(f"🛡️ Admin {user['id']} usando email asignado: {email} (verificación case-insensitive)")
        
        # Verificar estado del usuario antes de la búsqueda
        user_status = db.execute_query(
            "SELECT is_blocked, blocked_reason FROM users WHERE id = %s",
            (user['id'],)
        )
        
        if user_status and user_status[0]['is_blocked']:
            reason = user_status[0]['blocked_reason'] or "Usuario bloqueado"
            return JSONResponse(
                status_code=403,
                content={"error": f"Usuario bloqueado: {reason}"}
            )
        
        # Realizar búsqueda
        logger.info(f"🔍 Búsqueda Disney para {email} (usuario: {user['id']}, tipo: {'super_admin' if user.get('isSuperAdmin') else 'admin' if user.get('isAdmin') else 'user'})")
        result = disney_searcher.search_disney_codes(email, user['id'])
        
        if result and result.get('found'):
            logger.info(f"✅ Código Disney encontrado para {email}: {result['code']}")
            return JSONResponse(content={
                "found": True,
                "result": {
                    "code": result['code'],
                    "type": result['type'],
                    "email": result['email'],
                    "subject": result['subject'],
                    "date": result['date']
                }
            })
        else:
            logger.info(f"ℹ️ No se encontraron códigos Disney para {email}")
            return JSONResponse(content={"found": False})
            
    except Exception as e:
        logger.error(f"Error en búsqueda Disney API: {e}")
        
        # Manejar diferentes tipos de errores
        error_message = str(e)
        if "Usuario bloqueado" in error_message:
            return JSONResponse(
                status_code=403,
                content={"error": error_message}
            )
        elif "configuración IMAP" in error_message:
            return JSONResponse(
                status_code=400,
                content={"error": f"Error de configuración: {error_message}"}
            )
        else:
            return JSONResponse(
                status_code=500,
                content={"error": f"Error en búsqueda: {error_message[:100]}"}
            )

# Middleware para logging de requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.now()
    
    # Procesar request
    response = await call_next(request)
    
    # Calcular tiempo de procesamiento
    process_time = (datetime.now() - start_time).total_seconds()
    
    # Log solo requests importantes o errores
    if response.status_code >= 400 or process_time > 2.0:
        logger.info(
            f"{request.method} {request.url.path} - "
            f"Status: {response.status_code} - "
            f"Time: {process_time:.2f}s"
        )
    
    return response

# Manejadores de errores
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    logger.error(f"Error 500: {exc}")
    return templates.TemplateResponse("500.html", {"request": request}, status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
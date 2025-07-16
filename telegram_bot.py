import logging
import asyncio
import os
import zipfile
from datetime import datetime, timedelta
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from telegram.helpers import escape_markdown
from telegram.error import NetworkError, TimedOut, RetryAfter
from config import BOT_TOKEN, SUPER_ADMIN_IDS, DISNEY_PATTERNS, is_super_admin, get_primary_super_admin
from database import db
from disney_search import disney_searcher

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

class DisneyBot:
    def __init__(self):
        self.app = Application.builder().token(BOT_TOKEN).build()
        self.setup_handlers()
        self.restart_count = 0
        self.max_restarts = 10
        self.shutdown_event = None
    
    def setup_handlers(self):
        """Configura los manejadores de comandos"""
        # Comandos principales
        self.app.add_handler(CommandHandler("start", self.start_command))
        self.app.add_handler(CommandHandler("add", self.add_command))
        self.app.add_handler(CommandHandler("del", self.del_command))
        self.app.add_handler(CommandHandler("list", self.list_command))
        self.app.add_handler(CommandHandler("addimap", self.addimap_command))
        self.app.add_handler(CommandHandler("delimap", self.delimap_command))
        self.app.add_handler(CommandHandler("deluser", self.deluser_command))
        self.app.add_handler(CommandHandler("free", self.free_command))
        self.app.add_handler(CommandHandler("check", self.check_command))
        self.app.add_handler(CommandHandler("addadmin", self.addadmin_command))
        self.app.add_handler(CommandHandler("deladmin", self.deladmin_command))
        self.app.add_handler(CommandHandler("unblock", self.unblock_command))
        self.app.add_handler(CommandHandler("blocked", self.blocked_command))
        
        # Manejador de mensajes de texto
        self.app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))
        
        # Manejador de errores
        self.app.add_error_handler(self.error_handler)
    
    async def error_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Maneja errores del bot"""
        logger.error(f"Bot error: {context.error}")
        
        if isinstance(context.error, NetworkError):
            logger.warning("Error de red, reintentando...")
            await asyncio.sleep(5)
        elif isinstance(context.error, TimedOut):
            logger.warning("Timeout, reintentando...")
            await asyncio.sleep(3)
        elif isinstance(context.error, RetryAfter):
            logger.warning(f"Rate limit, esperando {context.error.retry_after} segundos")
            await asyncio.sleep(context.error.retry_after)
    
    async def check_super_admin_only(self, update: Update) -> bool:
        """Verifica si el usuario es SOLO super administrador"""
        user_id = update.effective_user.id
        
        if not is_super_admin(user_id):
            await update.message.reply_text("❌ Este comando está restringido solo a super administradores")
            return False
        
        return True

    async def check_admin_permissions(self, update: Update) -> bool:
        """Verifica si el usuario tiene permisos de administrador (super admin o admin normal)"""
        user_id = update.effective_user.id
        
        if is_super_admin(user_id):
            return True
        
        admin_data = db.execute_query(
            "SELECT is_admin FROM users WHERE id = %s AND is_admin = TRUE",
            (user_id,)
        )
        
        if not admin_data:
            await update.message.reply_text("❌ Este comando requiere permisos de administrador")
            return False
        
        return True

    async def can_use_email_restricted(self, user_id: int, email: str) -> bool:
        """✅ CORREGIDO: Verifica si el usuario puede usar un email específico (VERSIÓN CASE-INSENSITIVE)"""
        # Super admins tienen acceso a todos los emails
        if is_super_admin(user_id):
            return True
        
        # Verificar si es admin normal - solo puede usar emails asignados específicamente
        admin_data = db.execute_query(
            "SELECT is_admin FROM users WHERE id = %s AND is_admin = TRUE",
            (user_id,)
        )
        
        if admin_data:
            # Admin normal: solo emails asignados específicamente (comparación case-insensitive)
            # ✅ CORRECCIÓN: Usar LOWER() en SQL para comparación case-insensitive
            assigned_email = db.execute_query(
                "SELECT id FROM user_emails WHERE user_id = %s AND LOWER(email) = LOWER(%s)",
                (user_id, email)
            )
            return bool(assigned_email)
        
        # Usuario normal: verificar acceso libre o email asignado
        user_data = db.execute_query(
            "SELECT free_access FROM users WHERE id = %s",
            (user_id,)
        )
        
        if user_data and user_data[0]['free_access']:
            return True
        
        # Verificar email asignado para usuario normal (comparación case-insensitive)
        # ✅ CORRECCIÓN: Usar LOWER() en SQL para comparación case-insensitive
        assigned_email = db.execute_query(
            "SELECT id FROM user_emails WHERE user_id = %s AND LOWER(email) = LOWER(%s)",
            (user_id, email)
        )
        
        return bool(assigned_email)
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /start"""
        user = update.effective_user
        user_id = user.id
        
        # Verificar si es super admin
        if is_super_admin(user_id):
            await self.send_admin_welcome(update)
            return
        
        # Verificar si el usuario está autorizado
        user_data = db.execute_query(
            "SELECT id, username, first_name, is_admin, free_access, expires_at, is_active, is_blocked, blocked_reason FROM users WHERE id = %s",
            (user_id,)
        )
        
        if not user_data:
            # Usuario no autorizado - notificar a todos los super admins
            await self.notify_new_user(context, user)
            await update.message.reply_text(
                "❌ No estás autorizado para usar este bot.\n"
                "📧 Contacta al administrador para obtener acceso."
            )
            return
        
        user_info = user_data[0]
        
        # Verificar si está bloqueado
        if user_info['is_blocked']:
            reason = user_info['blocked_reason'] or "Usuario bloqueado"
            await update.message.reply_text(f"🚫 Tu cuenta está bloqueada: {reason}")
            return
        
        # Verificar si está activo y no expirado
        if not user_info['is_active']:
            await update.message.reply_text("❌ Tu cuenta está desactivada.")
            return
        
        if user_info['expires_at'] and datetime.now() > user_info['expires_at']:
            await update.message.reply_text("⏰ Tu acceso ha expirado. Contacta al administrador.")
            return
        
        # Enviar bienvenida personalizada
        await self.send_user_welcome(update, user_info)
    
    async def send_admin_welcome(self, update: Update):
        """Mensaje de bienvenida diferenciado para Super Admin vs Admin"""
        user_id = update.effective_user.id
        
        if is_super_admin(user_id):
            # Mensaje para Super Administrador
            message = (
                "👑 **Bienvenido Super Administrador**\n\n"
                "🔧 **Comandos de Super Admin:**\n"
                "• `/add <user_id> <email1> [email2...]` - Añadir cualquier email a usuario\n"
                "• `/del <user_id> <email1> [email2...]` - Eliminar cualquier email\n"
                "• `/list [user_id]` - Listar usuarios/emails\n"
                "• `/addimap <domain> <email> <password> <server>` - Configurar IMAP\n"
                "• `/delimap <domain>` - Eliminar config IMAP\n"
                "• `/deluser <user_id>` - Eliminar usuario\n"
                "• `/free <user_id>` - Dar acceso libre\n"
                "• `/free <user_id> remove_admin` - Quitar permisos de admin\n"
                "• `/addadmin <user_id> <email1> [email2...]` - Agregar admin con emails específicos\n"
                "• `/deladmin <user_id>` - Quitar administrador\n"
                "• `/unblock <user_id>` - Desbloquear usuario\n"
                "• `/blocked` - Listar usuarios bloqueados\n"
                "• `/check <email>` - Buscar códigos Disney (cualquier email)\n\n"
                "🏰 **Acceso total al sistema**\n"
                "⚠️ **Recibes notificaciones de seguridad**"
            )
        else:
            # Obtener emails asignados al admin
            admin_emails = db.execute_query(
                "SELECT email FROM user_emails WHERE user_id = %s",
                (user_id,)
            )
            
            email_count = len(admin_emails) if admin_emails else 0
            
            # Mensaje para Administrador normal
            message = (
                "🛡️ **Bienvenido Administrador**\n\n"
                f"📧 **Tienes {email_count} emails asignados**\n\n"
                "🔧 **Comandos disponibles:**\n"
                "• `/add <user_id> <email>` - Añadir emails (solo tus emails asignados)\n"
                "• `/del <user_id> <email>` - Eliminar emails (solo tus emails asignados)\n"
                "• `/list [user_id]` - Listar usuarios/emails\n"
                "• `/deluser <user_id>` - Eliminar usuario\n"
                "• `/check <email>` - Buscar códigos Disney (solo tus emails asignados)\n\n"
                "📧 **RESTRICCIÓN IMPORTANTE:**\n"
                "• Solo puedes gestionar emails que estén asignados a ti\n"
                "• Solo puedes usar emails asignados específicamente a tu cuenta\n"
                "• Tu cuenta será bloqueada si cambias emails durante búsquedas\n\n"
                "🚫 **NO disponible para ti:**\n"
                "• Configuración IMAP\n"
                "• Gestión de administradores\n"
                "• Gestión de usuarios bloqueados\n"
                "• Dar acceso libre a usuarios\n"
                "• Acceso a emails no asignados"
            )
        
        await update.message.reply_text(message, parse_mode='Markdown')
    
    async def send_user_welcome(self, update: Update, user_info):
        """Mensaje de bienvenida para usuario normal"""
        username = user_info['username'] or user_info['first_name'] or "Usuario"
        
        # Obtener emails asignados
        emails = db.execute_query(
            "SELECT email FROM user_emails WHERE user_id = %s",
            (user_info['id'],)
        )
        
        email_count = len(emails) if emails else 0
        
        # Calcular días restantes
        days_left = "∞"
        if user_info['expires_at']:
            time_left = user_info['expires_at'] - datetime.now()
            days_left = max(0, time_left.days)
        
        message = (
            f"🎉 **¡Bienvenido {username}!**\n\n"
            f"📊 **Tu información:**\n"
            f"📧 Emails asignados: {email_count}\n"
            f"⏰ Días restantes: {days_left}\n"
            f"🔓 Acceso libre: {'Sí' if user_info['free_access'] else 'No'}\n\n"
            f"🏰 **Comandos disponibles:**\n"
            f"• `/check <email>` - Buscar códigos Disney\n"
            f"• `/add <user_id> <email>` - Agregar email\n"
            f"• `/del <user_id> <email>` - Eliminar email\n\n"
            f"💡 **Uso:** Envía `/check tu@email.com` para buscar códigos Disney\n"
            f"📧 **Restricción:** Solo puedes usar emails asignados a ti.\n"
            f"⚠️ **Importante:** No cambies emails durante búsquedas."
        )
        
        await update.message.reply_text(message, parse_mode='Markdown')
    
    async def notify_new_user(self, context: ContextTypes.DEFAULT_TYPE, user):
        """Notifica a todos los super admins sobre nuevo usuario"""
        try:
            username_safe = escape_markdown(user.username if user.username else 'No establecido', version=2)
            name_safe = escape_markdown(user.full_name, version=2)
            
            message = (
                "🆕 **Nuevo usuario detectado**\n\n"
                f"🆔 ID: `{user.id}`\n"
                f"👤 Nombre: {name_safe}\n"
                f"📝 Username: @{username_safe}\n"
                f"📅 Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            
            # Enviar a todos los super admins
            for admin_id in SUPER_ADMIN_IDS:
                try:
                    await context.bot.send_message(
                        chat_id=admin_id,
                        text=message,
                        parse_mode='MarkdownV2'
                    )
                except Exception as e:
                    logger.error(f"Error notificando a super admin {admin_id}: {e}")
                    
        except Exception as e:
            logger.error(f"Error notificando nuevo usuario: {e}")
    
    async def unblock_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /unblock <user_id> - SOLO SUPER ADMINS"""
        if not await self.check_super_admin_only(update):
            return
        
        if len(context.args) != 1:
            await update.message.reply_text("❌ Uso: /unblock <user_id>")
            return
        
        try:
            user_id = int(context.args[0])
            
            # Desbloquear usuario
            result = db.execute_query("""
                UPDATE users 
                SET is_blocked = FALSE, blocked_reason = NULL, blocked_at = NULL
                WHERE id = %s
            """, (user_id,))
            
            if result > 0:
                await update.message.reply_text(f"✅ Usuario {user_id} desbloqueado correctamente")
            else:
                await update.message.reply_text(f"❌ Usuario {user_id} no encontrado")
                
        except ValueError:
            await update.message.reply_text("❌ El user_id debe ser un número")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def blocked_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /blocked - Lista usuarios bloqueados - SOLO SUPER ADMINS"""
        if not await self.check_super_admin_only(update):
            return
        
        try:
            blocked_users = db.execute_query("""
                SELECT id, username, first_name, blocked_reason, blocked_at
                FROM users 
                WHERE is_blocked = TRUE
                ORDER BY blocked_at DESC
            """)
            
            if not blocked_users:
                await update.message.reply_text("📋 No hay usuarios bloqueados")
                return
            
            # Crear archivo con usuarios bloqueados
            filename = f"usuarios_bloqueados_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("USUARIOS BLOQUEADOS\n")
                f.write("=" * 50 + "\n\n")
                
                for user in blocked_users:
                    f.write(f"ID: {user['id']}\n")
                    f.write(f"Username: {user['username'] or 'No establecido'}\n")
                    f.write(f"Nombre: {user['first_name'] or 'No establecido'}\n")
                    f.write(f"Razón: {user['blocked_reason'] or 'Sin razón especificada'}\n")
                    f.write(f"Bloqueado: {user['blocked_at']}\n")
                    f.write("-" * 30 + "\n\n")
                
                f.write(f"Total: {len(blocked_users)} usuarios bloqueados")
            
            # Enviar archivo
            with open(filename, 'rb') as f:
                await update.message.reply_document(
                    document=f,
                    filename=filename,
                    caption=f"🚫 Lista de {len(blocked_users)} usuarios bloqueados"
                )
            
            # Limpiar archivo temporal
            os.remove(filename)
            
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def check_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """✅ CORREGIDO: Comando /check <email> - VERSIÓN CON CASE-INSENSITIVE"""
        user_id = update.effective_user.id
        
        # Verificar autorización
        if not await self.check_user_access(update):
            return
        
        if len(context.args) != 1:
            await update.message.reply_text(
                "❌ Uso: /check <email>\n\n"
                "📧 Ejemplo: /check usuario@gmail.com"
            )
            return
        
        email = context.args[0].strip().lower()
        
        # Validar formato de email
        if '@' not in email or '.' not in email.split('@')[1]:
            await update.message.reply_text("❌ Formato de email inválido")
            return
        
        # ✅ CORRECCIÓN: Usar la función de verificación case-insensitive
        if not await self.can_use_email_restricted(user_id, email):
            await update.message.reply_text(
                "❌ No tienes permiso para usar este email.\n"
                "📧 Solo puedes usar emails específicamente asignados a tu cuenta."
            )
            return
        
        # Realizar búsqueda
        status_msg = await update.message.reply_text("🔍 Buscando códigos Disney...")
        
        try:
            result = disney_searcher.search_disney_codes(email, user_id)
            
            if result and result.get('found'):
                # Escapar caracteres especiales para Markdown
                safe_code = escape_markdown(result['code'], version=2)
                safe_email = escape_markdown(result['email'], version=2)
                safe_type = escape_markdown(result['type'], version=2)
                safe_subject = escape_markdown(result['subject'][:100] + "..." if len(result['subject']) > 100 else result['subject'], version=2)
                safe_date = escape_markdown(result['date'], version=2)
                safe_pattern = escape_markdown(result['pattern_used'], version=2)
                
                message = (
                    "✅ **Código Disney encontrado**\n\n"
                    f"🏰 **Código:** `{safe_code}`\n"
                    f"📧 **Email:** {safe_email}\n"
                    f"📝 **Asunto:** {safe_subject}\n"
                    f"📅 **Fecha:** {safe_date}\n"
                )
                
                await status_msg.edit_text(message, parse_mode='MarkdownV2')
                
                # ✅ Log de éxito con case sensitivity
                logger.info(f"✅ Código Disney encontrado para {email} (user {user_id}) - case insensitive OK")
            else:
                message = (
                    "❌ **No se encontraron códigos Disney**\n\n"
                    f"📧 **Email:** {escape_markdown(email, version=2)}\n"
                    f"📅 **Período:** Últimos 2 días\n"
                    f"🔍 **Patrones probados:** {len(DISNEY_PATTERNS)}"
                )
                
                await status_msg.edit_text(message, parse_mode='MarkdownV2')
            
        except Exception as e:
            logger.error(f"Error en búsqueda Disney: {e}")
            error_message = (
                f"❌ Error en la búsqueda\n\n"
                f"📧 Email: {email}\n"
                f"🚫 Error: {str(e)[:200]}..."
            )
            
            await status_msg.edit_text(error_message)
    
    async def check_user_access(self, update: Update) -> bool:
        """Verifica si el usuario tiene acceso al bot"""
        user_id = update.effective_user.id
        
        if is_super_admin(user_id):
            return True
        
        user_data = db.execute_query(
            "SELECT is_active, expires_at, is_blocked, blocked_reason FROM users WHERE id = %s",
            (user_id,)
        )
        
        if not user_data:
            await update.message.reply_text("❌ No tienes acceso al bot")
            return False
        
        user_info = user_data[0]
        
        if user_info['is_blocked']:
            reason = user_info['blocked_reason'] or "Usuario bloqueado"
            await update.message.reply_text(f"🚫 Tu cuenta está bloqueada: {reason}")
            return False
        
        if not user_info['is_active']:
            await update.message.reply_text("❌ Tu cuenta está desactivada")
            return False
        
        if user_info['expires_at'] and datetime.now() > user_info['expires_at']:
            await update.message.reply_text("⏰ Tu acceso ha expirado")
            return False
        
        return True
    
    async def add_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /add <user_id> <email1> [email2...] - RESTRINGIDO PARA ADMINS"""
        if not await self.check_admin_permissions(update):
            return
        
        if len(context.args) < 2:
            await update.message.reply_text("❌ Uso: /add <user_id> <email1> [email2...]")
            return
        
        try:
            user_id = int(context.args[0])
            emails = context.args[1:]
            
            # RESTRICCIÓN: Admins normales solo pueden asignar emails que ellos tienen
            if not is_super_admin(update.effective_user.id):
                # Obtener emails asignados al admin
                admin_emails = db.execute_query(
                    "SELECT email FROM user_emails WHERE user_id = %s",
                    (update.effective_user.id,)
                )
                
                if not admin_emails:
                    await update.message.reply_text(
                        "❌ No tienes emails asignados para gestionar otros usuarios.\n"
                        "📧 Solo puedes asignar emails que tengas asignados a ti."
                    )
                    return
                
                admin_email_list = [row['email'] for row in admin_emails]
                
                # Verificar que todos los emails solicitados están en los emails del admin
                unauthorized_emails = [email for email in emails if email not in admin_email_list]
                
                if unauthorized_emails:
                    await update.message.reply_text(
                        f"❌ No puedes asignar estos emails (no los tienes asignados): {', '.join(unauthorized_emails)}\n\n"
                        f"✅ Tus emails disponibles: {', '.join(admin_email_list)}"
                    )
                    return
            
            # Verificar/crear usuario
            user_exists = db.execute_query("SELECT id FROM users WHERE id = %s", (user_id,))
            
            if not user_exists:
                # Crear usuario con 30 días de acceso
                expires_at = datetime.now() + timedelta(days=30)
                db.execute_query("""
                    INSERT INTO users (id, expires_at, is_active)
                    VALUES (%s, %s, %s)
                """, (user_id, expires_at, True))
            
            # Añadir emails
            added_emails = []
            for email in emails:
                try:
                    db.execute_query("""
                        INSERT INTO user_emails (user_id, email)
                        VALUES (%s, %s)
                        ON CONFLICT (user_id, email) DO NOTHING
                    """, (user_id, email))
                    added_emails.append(email)
                except Exception as e:
                    logger.error(f"Error añadiendo email {email}: {e}")
            
            message = f"✅ Usuario {user_id} actualizado\n📧 Emails añadidos: {len(added_emails)}"
            if added_emails:
                emails_text = "\n".join([f"• {email}" for email in added_emails])
                message += f"\n\n**Emails:**\n{emails_text}"
            
            # Nota para admins normales
            if not is_super_admin(update.effective_user.id):
                message += f"\n\n🛡️ *Agregado como administrador - Solo emails asignados a ti*"
            
            await update.message.reply_text(message, parse_mode='Markdown')
            
        except ValueError:
            await update.message.reply_text("❌ El user_id debe ser un número")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def del_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /del <user_id> <email1> [email2...] - RESTRINGIDO PARA ADMINS"""
        if not await self.check_admin_permissions(update):
            return
        
        if len(context.args) < 2:
            await update.message.reply_text("❌ Uso: /del <user_id> <email1> [email2...]")
            return
        
        try:
            user_id = int(context.args[0])
            emails = context.args[1:]
            
            # RESTRICCIÓN: Admins normales solo pueden eliminar emails que ellos tienen asignados
            if not is_super_admin(update.effective_user.id):
                # Obtener emails asignados al admin
                admin_emails = db.execute_query(
                    "SELECT email FROM user_emails WHERE user_id = %s",
                    (update.effective_user.id,)
                )
                
                if not admin_emails:
                    await update.message.reply_text(
                        "❌ No tienes emails asignados para gestionar otros usuarios."
                    )
                    return
                
                admin_email_list = [row['email'] for row in admin_emails]
                
                # Verificar que todos los emails a eliminar están en los emails del admin
                unauthorized_emails = [email for email in emails if email not in admin_email_list]
                
                if unauthorized_emails:
                    await update.message.reply_text(
                        f"❌ No puedes eliminar estos emails (no los tienes asignados): {', '.join(unauthorized_emails)}\n\n"
                        f"✅ Tus emails disponibles: {', '.join(admin_email_list)}"
                    )
                    return
            
            deleted_count = 0
            for email in emails:
                result = db.execute_query("""
                    DELETE FROM user_emails 
                    WHERE user_id = %s AND email = %s
                """, (user_id, email))
                if result > 0:
                    deleted_count += 1
            
            message = f"✅ Se eliminaron {deleted_count} emails del usuario {user_id}"
            
            # Nota para admins normales
            if not is_super_admin(update.effective_user.id):
                message += f"\n\n🛡️ *Eliminado como administrador - Solo emails asignados a ti*"
            
            await update.message.reply_text(message, parse_mode='Markdown')
            
        except ValueError:
            await update.message.reply_text("❌ El user_id debe ser un número")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def list_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /list [user_id]"""
        if not await self.check_admin_permissions(update):
            return
        
        try:
            if context.args:
                # Listar emails de un usuario específico
                user_id = int(context.args[0])
                await self.list_user_emails(update, user_id)
            else:
                # Listar todos los usuarios
                await self.list_all_users(update)
                
        except ValueError:
            await update.message.reply_text("❌ El user_id debe ser un número")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def list_user_emails(self, update: Update, user_id: int):
        """Lista emails de un usuario específico"""
        user_data = db.execute_query(
            "SELECT username, first_name FROM users WHERE id = %s",
            (user_id,)
        )
        
        if not user_data:
            await update.message.reply_text(f"❌ Usuario {user_id} no encontrado")
            return
        
        emails = db.execute_query(
            "SELECT email FROM user_emails WHERE user_id = %s ORDER BY email",
            (user_id,)
        )
        
        # Crear archivo temporal
        filename = f"emails_{user_id}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Emails del usuario {user_id}\n")
            f.write("=" * 30 + "\n\n")
            
            if emails:
                for email_row in emails:
                    f.write(f"{email_row['email']}\n")
                f.write(f"\nTotal: {len(emails)} emails")
            else:
                f.write("No hay emails asignados")
        
        # Enviar archivo
        with open(filename, 'rb') as f:
            await update.message.reply_document(
                document=f,
                filename=filename,
                caption=f"📧 Emails del usuario {user_id}"
            )
        
        # Limpiar archivo temporal
        os.remove(filename)
    
    async def list_all_users(self, update: Update):
        """Lista todos los usuarios en archivos separados"""
        users = db.execute_query("""
            SELECT id, username, first_name, is_admin, free_access, 
                   expires_at, is_active, created_at
            FROM users ORDER BY id
        """)
        
        if not users:
            await update.message.reply_text("📭 No hay usuarios registrados")
            return
        
        # Crear directorio temporal
        temp_dir = "temp_users"
        os.makedirs(temp_dir, exist_ok=True)
        
        files_created = []
        
        for user in users:
            user_id = user['id']
            
            # Obtener emails del usuario
            emails = db.execute_query(
                "SELECT email FROM user_emails WHERE user_id = %s ORDER BY email",
                (user_id,)
            )
            
            # Crear archivo para este usuario
            filename = f"{temp_dir}/user_{user_id}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"USUARIO {user_id}\n")
                f.write("=" * 30 + "\n\n")
                
                f.write(f"Username: {user['username'] or 'No establecido'}\n")
                f.write(f"Nombre: {user['first_name'] or 'No establecido'}\n")
                f.write(f"Admin: {'Sí' if user['is_admin'] else 'No'}\n")
                f.write(f"Acceso libre: {'Sí' if user['free_access'] else 'No'}\n")
                f.write(f"Activo: {'Sí' if user['is_active'] else 'No'}\n")
                f.write(f"Creado: {user['created_at']}\n")
                f.write(f"Expira: {user['expires_at'] or 'Sin expiración'}\n\n")
                
                f.write("EMAILS ASIGNADOS:\n")
                f.write("-" * 20 + "\n")
                
                if emails:
                    for email_row in emails:
                        f.write(f"• {email_row['email']}\n")
                    f.write(f"\nTotal: {len(emails)} emails")
                else:
                    f.write("No hay emails asignados\n")
            
            files_created.append(filename)
        
        # Crear ZIP
        zip_filename = f"usuarios_completo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        with zipfile.ZipFile(zip_filename, 'w') as zipf:
            for file_path in files_created:
                zipf.write(file_path, os.path.basename(file_path))
        
        # Enviar ZIP
        with open(zip_filename, 'rb') as f:
            await update.message.reply_document(
                document=f,
                filename=zip_filename,
                caption=f"📊 Lista completa de {len(users)} usuarios"
            )
        
        # Limpiar archivos temporales
        for file_path in files_created:
            os.remove(file_path)
        os.rmdir(temp_dir)
        os.remove(zip_filename)
    
    async def addimap_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /addimap [domain] [email] [password] [server] - SOLO SUPER ADMINS"""
        if not await self.check_super_admin_only(update):
            return
        
        # Si no hay argumentos, mostrar dominios existentes
        if len(context.args) == 0:
            try:
                configs = db.execute_query("""
                    SELECT domain, email, server, port, created_at
                    FROM imap_configs 
                    ORDER BY domain
                """)
                
                if not configs:
                    await update.message.reply_text(
                        "📭 **No hay configuraciones IMAP**\n\n"
                        "💡 Uso: `/addimap <domain> <email> <password> <server>`\n"
                        "📧 Ejemplo: `/addimap gmail.com admin@gmail.com password123 imap.gmail.com`"
                    )
                    return
                
                # Crear mensaje con dominios existentes
                message = f"📋 **Configuraciones IMAP ({len(configs)}):**\n\n"
                
                for config in configs:
                    created_date = config['created_at'].strftime('%Y-%m-%d') if config['created_at'] else 'N/A'
                    message += (
                        f"🔧 **{config['domain']}**\n"
                        f"📧 Email: `{config['email']}`\n"
                        f"🌐 Servidor: `{config['server']}:{config['port']}`\n"
                        f"📅 Creado: {created_date}\n\n"
                    )
                
                message += (
                    "💡 **Comandos:**\n"
                    "• `/addimap <domain> <email> <password> <server>` - Agregar/actualizar\n"
                    "• `/delimap <domain>` - Eliminar configuración\n"
                    "• `/addimap` - Ver esta lista"
                )
                
                await update.message.reply_text(message, parse_mode='Markdown')
                return
                
            except Exception as e:
                await update.message.reply_text(f"❌ Error consultando configuraciones: {str(e)}")
                return
        
        # Si hay argumentos, procesar como antes
        if len(context.args) < 4:
            await update.message.reply_text(
                "❌ Uso: /addimap <domain> <email> <password> <server>\n\n"
                "📧 Ejemplo: /addimap gmail.com admin@gmail.com password123 imap.gmail.com\n"
                "💡 O usa /addimap para ver configuraciones existentes"
            )
            return
        
        try:
            domain, email, password, server = context.args[:4]
            
            # Insertar o actualizar configuración
            db.execute_query("""
                INSERT INTO imap_configs (domain, email, password, server, created_by)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (domain) DO UPDATE SET
                email = EXCLUDED.email,
                password = EXCLUDED.password,
                server = EXCLUDED.server,
                created_by = EXCLUDED.created_by
            """, (domain, email, password, server, update.effective_user.id))
            
            await update.message.reply_text(f"✅ Configuración IMAP para {domain} guardada")
            
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def delimap_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /delimap <domain> - SOLO SUPER ADMINS"""
        if not await self.check_super_admin_only(update):
            return
        
        if len(context.args) != 1:
            await update.message.reply_text("❌ Uso: /delimap <domain>")
            return
        
        try:
            domain = context.args[0]
            
            result = db.execute_query(
                "DELETE FROM imap_configs WHERE domain = %s",
                (domain,)
            )
            
            if result > 0:
                await update.message.reply_text(f"✅ Configuración IMAP para {domain} eliminada")
            else:
                await update.message.reply_text(f"❌ No se encontró configuración para {domain}")
                
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def deluser_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """✅ CORREGIDO: Comando /deluser <user_id> con eliminación segura"""
        if not await self.check_admin_permissions(update):
            return
        
        if len(context.args) != 1:
            await update.message.reply_text("❌ Uso: /deluser <user_id>")
            return
        
        try:
            user_id = int(context.args[0])
            
            # Usar la nueva función de eliminación segura que maneja constraints
            db.safe_delete_user(user_id)
            
            await update.message.reply_text(f"✅ Usuario {user_id} eliminado completamente con todos sus registros relacionados")
                
        except ValueError as e:
            if "debe ser un número" in str(e):
                await update.message.reply_text("❌ El user_id debe ser un número")
            else:
                await update.message.reply_text(f"❌ {str(e)}")
        except Exception as e:
            logger.error(f"Error en deluser_command: {e}")
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def free_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /free <user_id> [remove_admin] - SOLO SUPER ADMINS"""
        if not await self.check_super_admin_only(update):
            return
        
        if len(context.args) < 1 or len(context.args) > 2:
            await update.message.reply_text(
                "❌ Uso: /free <user_id> [remove_admin]\n\n"
                "• `/free 123456789` - Dar acceso libre\n"
                "• `/free 123456789 remove_admin` - Quitar permisos de admin"
            )
            return
        
        try:
            user_id = int(context.args[0])
            remove_admin = len(context.args) == 2 and context.args[1].lower() == 'remove_admin'
            
            if remove_admin:
                if is_super_admin(user_id):
                    await update.message.reply_text("❌ No se pueden quitar permisos a un super administrador")
                    return
                
                # Quitar permisos de admin y acceso libre
                result = db.execute_query("""
                    UPDATE users SET is_admin = FALSE, free_access = FALSE 
                    WHERE id = %s
                """, (user_id,))
                
                if result > 0:
                    await update.message.reply_text(f"✅ Permisos de administrador y acceso libre removidos del usuario {user_id}")
                else:
                    await update.message.reply_text(f"❌ Usuario {user_id} no encontrado")
            else:
                # Dar acceso libre (comportamiento original)
                result = db.execute_query("""
                    UPDATE users SET free_access = TRUE 
                    WHERE id = %s
                """, (user_id,))
                
                if result > 0:
                    await update.message.reply_text(f"✅ Usuario {user_id} ahora tiene acceso libre a todos los emails")
                else:
                    await update.message.reply_text(f"❌ Usuario {user_id} no encontrado")
                    
        except ValueError:
            await update.message.reply_text("❌ El user_id debe ser un número")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def addadmin_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /addadmin <user_id> <email1> [email2...] - SOLO SUPER ADMINS"""
        if not await self.check_super_admin_only(update):
            return
        
        if len(context.args) < 2:
            await update.message.reply_text(
                "❌ Uso: /addadmin <user_id> <email1> [email2...]\n\n"
                "📧 Especifica los emails que el admin podrá usar:\n"
                "• `/addadmin 123456789 admin@gmail.com admin@yahoo.com`\n"
                "• El admin solo podrá usar esos emails específicos"
            )
            return
        
        try:
            new_admin_id = int(context.args[0])
            emails = context.args[1:]
            
            if is_super_admin(new_admin_id):
                await update.message.reply_text("❌ Este usuario ya es super administrador")
                return
            
            # Validar formato de emails
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            invalid_emails = [email for email in emails if not re.match(email_pattern, email)]
            
            if invalid_emails:
                await update.message.reply_text(f"❌ Emails con formato inválido: {', '.join(invalid_emails)}")
                return
            
            # Verificar si el usuario existe
            user_exists = db.execute_query("SELECT id FROM users WHERE id = %s", (new_admin_id,))
            
            if not user_exists:
                # Crear usuario admin con emails específicos
                expires_at = datetime.now() + timedelta(days=365)  # 1 año para admins
                db.execute_query("""
                    INSERT INTO users (id, is_admin, is_active, expires_at)
                    VALUES (%s, %s, %s, %s)
                """, (new_admin_id, True, True, expires_at))
                
                # Agregar emails asignados
                for email in emails:
                    try:
                        db.execute_query("""
                            INSERT INTO user_emails (user_id, email)
                            VALUES (%s, %s)
                            ON CONFLICT (user_id, email) DO NOTHING
                        """, (new_admin_id, email))
                    except Exception as e:
                        logger.error(f"Error agregando email {email}: {e}")
                
                await update.message.reply_text(
                    f"✅ Usuario {new_admin_id} creado como administrador\n"
                    f"📧 Emails asignados: {len(emails)}\n"
                    f"📝 Emails: {', '.join(emails[:3])}" + 
                    (f" (+{len(emails)-3} más)" if len(emails) > 3 else "")
                )
            else:
                # Actualizar usuario existente y reemplazar emails
                db.execute_query("""
                    UPDATE users SET is_admin = TRUE, is_active = TRUE
                    WHERE id = %s
                """, (new_admin_id,))
                
                # Eliminar emails anteriores
                db.execute_query("DELETE FROM user_emails WHERE user_id = %s", (new_admin_id,))
                
                # Agregar nuevos emails
                for email in emails:
                    try:
                        db.execute_query("""
                            INSERT INTO user_emails (user_id, email)
                            VALUES (%s, %s)
                        """, (new_admin_id, email))
                    except Exception as e:
                        logger.error(f"Error agregando email {email}: {e}")
                
                await update.message.reply_text(
                    f"✅ Usuario {new_admin_id} promovido a administrador\n"
                    f"📧 Emails actualizados: {len(emails)}\n"
                    f"📝 Emails: {', '.join(emails[:3])}" + 
                    (f" (+{len(emails)-3} más)" if len(emails) > 3 else "")
                )
                
        except ValueError:
            await update.message.reply_text("❌ El user_id debe ser un número")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def deladmin_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /deladmin <user_id> - SOLO SUPER ADMINS"""
        if not await self.check_super_admin_only(update):
            return
        
        if len(context.args) != 1:
            await update.message.reply_text("❌ Uso: /deladmin <user_id>")
            return
        
        try:
            admin_id = int(context.args[0])
            
            if is_super_admin(admin_id):
                await update.message.reply_text("❌ No se pueden quitar permisos a un super administrador")
                return
            
            # Quitar permisos de admin
            result = db.execute_query("""
                UPDATE users SET is_admin = FALSE 
                WHERE id = %s
            """, (admin_id,))
            
            if result > 0:
                await update.message.reply_text(f"✅ Permisos de administrador removidos del usuario {admin_id}")
            else:
                await update.message.reply_text(f"❌ Usuario {admin_id} no encontrado")
                
        except ValueError:
            await update.message.reply_text("❌ El user_id debe ser un número")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Maneja mensajes de texto (para futuras funcionalidades)"""
        # Por ahora solo envía un mensaje de ayuda
        await update.message.reply_text(
            "💡 **Comandos disponibles:**\n\n"
            "🏰 `/check <email>` - Buscar códigos Disney\n"
            "📋 `/start` - Mostrar información de tu cuenta\n\n"
            "📧 **Ejemplo:** `/check usuario@gmail.com`",
            parse_mode='Markdown'
        )
    
    async def run_with_shutdown(self, shutdown_event):
        """Ejecuta el bot con manejo de cierre"""
        self.shutdown_event = shutdown_event
        
        try:
            logger.info("🤖 Inicializando bot de Telegram...")
            await self.app.initialize()
            
            logger.info("🤖 Iniciando bot de Telegram...")
            await self.app.start()
            
            # Iniciar polling con timeout personalizado
            await self.app.updater.start_polling(
                timeout=10,
                read_timeout=10,
                write_timeout=10,
                connect_timeout=10,
                pool_timeout=5
            )
            
            logger.info("✅ Bot de Telegram iniciado correctamente")
            
            # Esperar hasta que se señale el cierre
            try:
                await shutdown_event.wait()
                logger.info("🤖 Señal de cierre recibida para el bot")
            except asyncio.CancelledError:
                logger.info("🤖 Bot cancelado")
                raise
            
        except asyncio.CancelledError:
            logger.info("🤖 Bot de Telegram cancelado durante inicialización")
            raise
        except Exception as e:
            logger.error(f"❌ Error crítico en bot: {e}")
            raise
        finally:
            # Limpiar recursos
            try:
                logger.info("🤖 Deteniendo bot de Telegram...")
                
                if self.app.updater.running:
                    await self.app.updater.stop()
                
                await self.app.stop()
                await self.app.shutdown()
                
                logger.info("✅ Bot de Telegram detenido correctamente")
            except Exception as e:
                logger.error(f"❌ Error cerrando bot: {e}")

# Instancia global del bot
bot = DisneyBot()
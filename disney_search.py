import imaplib
import email
import re
import logging
import threading
import time
from datetime import datetime, timedelta
from email.header import decode_header
from config import DISNEY_PATTERNS, DISNEY_FROM_ADDRESSES, SUPER_ADMIN_IDS
from database import db

logger = logging.getLogger(__name__)

class DisneySearcher:
    def __init__(self):
        self.connections = {}
        self.verification_threads = {}
        
        # Patrones para detectar cambios de email
        self.email_change_patterns = [
            r'Se cambi(?:=C3=B3|ó) el correo electr(?:=C3=B3|ó)nico(?:=)?',
            r'Correo electr(?:=C3=B3|ó)nico de MyDisney actua(?:=)?',
            r';">[\s]*MyDisney unique email address updated[\s]*</td>'
        ]
    
    def get_imap_config(self, email_addr):
        """Obtiene configuración IMAP para un dominio"""
        try:
            if '@' not in email_addr:
                raise ValueError("Email inválido")
            
            domain = email_addr.split('@')[1]
            
            # Buscar configuración en BD
            config = db.execute_query(
                "SELECT email, password, server, port FROM imap_configs WHERE domain = %s",
                (domain,)
            )
            
            if not config:
                raise ValueError(f"No hay configuración IMAP para el dominio: {domain}")
            
            return {
                'email': config[0]['email'],
                'password': config[0]['password'],
                'server': config[0]['server'],
                'port': config[0]['port']
            }
        except Exception as e:
            logger.error(f"Error obteniendo configuración IMAP: {e}")
            raise
    
    def connect_imap(self, config):
        """Conecta a servidor IMAP con reintentos"""
        max_retries = 3
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                conn = imaplib.IMAP4_SSL(config['server'], config['port'])
                conn.login(config['email'], config['password'])
                conn.select('INBOX')
                return conn
            except Exception as e:
                logger.error(f"Error conectando IMAP (intento {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    raise
    
    def search_disney_codes(self, email_addr, user_id):
        """Busca códigos Disney en el email especificado"""
        conn = None
        try:
            # Verificar si el usuario está bloqueado
            user_status = db.execute_query(
                "SELECT is_blocked, blocked_reason FROM users WHERE id = %s",
                (user_id,)
            )
            
            if user_status and user_status[0]['is_blocked']:
                reason = user_status[0]['blocked_reason'] or "Usuario bloqueado"
                raise Exception(f"Usuario bloqueado: {reason}")
            
            config = self.get_imap_config(email_addr)
            conn = self.connect_imap(config)
            
            # Buscar emails de los últimos 2 días
            date_since = (datetime.now() - timedelta(days=2)).strftime("%d-%b-%Y")
            
            # Construir criterio de búsqueda
            search_criteria = []
            for from_addr in DISNEY_FROM_ADDRESSES:
                search_criteria.append(f'(FROM "{from_addr}" TO "{email_addr}" SINCE {date_since})')
            
            combined_criteria = f'OR {" ".join(search_criteria)}' if len(search_criteria) > 1 else search_criteria[0]
            
            # Buscar mensajes
            status, messages = conn.search(None, combined_criteria)
            
            if not messages[0]:
                logger.info(f"No se encontraron emails Disney para {email_addr}")
                return {'found': False, 'email': email_addr}
            
            # Procesar mensajes (más recientes primero)
            message_ids = messages[0].split()
            message_ids.reverse()
            
            # Probar cada patrón regex
            for msg_id in message_ids[:10]:  # Solo los 10 más recientes
                try:
                    # Obtener mensaje completo
                    status, msg_data = conn.fetch(msg_id, '(RFC822)')
                    if not msg_data or not msg_data[0] or not msg_data[0][1]:
                        continue
                        
                    raw_email = msg_data[0][1]
                    email_message = email.message_from_bytes(raw_email)
                    
                    # Extraer información del email
                    subject = self.decode_subject(email_message.get('Subject', ''))
                    from_addr = email_message.get('From', '')
                    date_str = email_message.get('Date', '')
                    
                    # Obtener cuerpo del mensaje
                    body = self.extract_body(email_message)
                    
                    if not body:
                        continue
                    
                    # Probar cada patrón Disney
                    for pattern_name, pattern in DISNEY_PATTERNS.items():
                        try:
                            regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                            match = regex.search(body)
                            
                            if match:
                                code = match.group(1) if match.groups() else match.group(0)
                                
                                # Limpiar código
                                code = code.strip()
                                
                                if not code:
                                    continue
                                
                                # Determinar tipo de código
                                code_type = self.determine_code_type(pattern_name, subject, from_addr)
                                
                                result = {
                                    'found': True,
                                    'code': code,
                                    'type': code_type,
                                    'email': email_addr,
                                    'subject': subject,
                                    'date': date_str,
                                    'pattern_used': pattern_name
                                }
                                
                                # Guardar búsqueda en BD
                                search_id = self.save_search_result(user_id, email_addr, code_type, code)
                                
                                # Programar verificación de cambio de email después de 40 segundos
                                if search_id:
                                    self.schedule_email_verification(search_id, user_id, email_addr, code)
                                
                                return result
                                
                        except re.error as e:
                            logger.error(f"Error en regex {pattern_name}: {e}")
                            continue
                        except Exception as e:
                            logger.error(f"Error procesando patrón {pattern_name}: {e}")
                            continue
                
                except Exception as e:
                    logger.error(f"Error procesando mensaje {msg_id}: {e}")
                    continue
            
            return {'found': False, 'email': email_addr}
            
        except Exception as e:
            logger.error(f"Error en búsqueda Disney para {email_addr}: {e}")
            raise Exception(f"Error en búsqueda: {str(e)}")
        finally:
            if conn:
                try:
                    conn.logout()
                except:
                    pass
    
    def decode_subject(self, subject):
        """Decodifica el asunto del email"""
        if not subject:
            return ""
        
        try:
            decoded_parts = decode_header(subject)
            decoded_subject = ""
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        try:
                            decoded_subject += part.decode(encoding, 'ignore')
                        except (UnicodeDecodeError, LookupError):
                            decoded_subject += part.decode('utf-8', 'ignore')
                    else:
                        decoded_subject += part.decode('utf-8', 'ignore')
                else:
                    decoded_subject += str(part)
            
            return decoded_subject
        except Exception as e:
            logger.error(f"Error decodificando subject: {e}")
            return str(subject)
    
    def extract_body(self, email_message):
        """Extrae el cuerpo del mensaje"""
        body = ""
        
        try:
            if email_message.is_multipart():
                for part in email_message.walk():
                    content_type = part.get_content_type()
                    if content_type in ["text/html", "text/plain"]:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body += payload.decode('utf-8', 'ignore')
                        except Exception as e:
                            logger.error(f"Error extrayendo parte del mensaje: {e}")
                            continue
            else:
                try:
                    payload = email_message.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', 'ignore')
                except Exception as e:
                    logger.error(f"Error extrayendo cuerpo del mensaje: {e}")
            
            return body
        except Exception as e:
            logger.error(f"Error general extrayendo cuerpo: {e}")
            return ""
    
    def determine_code_type(self, pattern_name, subject, from_addr):
        """Determina el tipo de código Disney basado en el patrón y contexto"""
        type_mapping = {
            'disney_code': 'Disney Plus Code',
            'disney_household': 'Disney Household Code', 
            'disney_mydisney': 'My Disney OTP'
        }
        
        return type_mapping.get(pattern_name, 'Disney Code')
    
    def save_search_result(self, user_id, email, result_type, result_code):
        """Guarda el resultado de búsqueda en la BD"""
        try:
            # CORREGIDO: Usar query específica para INSERT RETURNING en PostgreSQL
            conn = None
            cursor = None
            
            try:
                conn = db.get_connection()
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO disney_searches (user_id, email, result_type, result_code, verification_scheduled)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                """, (user_id, email, result_type, result_code, True))
                
                result = cursor.fetchone()
                conn.commit()
                
                if result:
                    search_id = result['id']
                    logger.info(f"✅ Búsqueda guardada con ID: {search_id}")
                    return search_id
                
                return None
                
            finally:
                if cursor:
                    cursor.close()
                if conn:
                    db.put_connection(conn)
            
        except Exception as e:
            logger.error(f"Error guardando resultado de búsqueda: {e}")
            return None
    
    def schedule_email_verification(self, search_id, user_id, email_addr, original_code):
        """Programa verificación de cambio de email después de 40 segundos"""
        try:
            # Guardar verificación programada
            db.execute_query("""
                INSERT INTO email_change_verifications (search_id, user_id, email, original_code)
                VALUES (%s, %s, %s, %s)
            """, (search_id, user_id, email_addr, original_code))
            
            # Crear thread para verificación
            thread_key = f"{user_id}_{email_addr}_{int(time.time())}"
            
            verification_thread = threading.Thread(
                target=self.verify_email_change,
                args=(search_id, user_id, email_addr, original_code),
                daemon=True
            )
            
            self.verification_threads[thread_key] = verification_thread
            verification_thread.start()
            
            logger.info(f"✅ Verificación programada para {email_addr} en 40 segundos")
            
        except Exception as e:
            logger.error(f"❌ Error programando verificación: {e}")
    
    def verify_email_change(self, search_id, user_id, email_addr, original_code):
        """Verifica si hubo cambio de email después de 40 segundos"""
        try:
            # Esperar 40 segundos
            time.sleep(40)
            
            logger.info(f"🔍 Verificando cambio de email para {email_addr}")
            
            # Conectar a email
            config = self.get_imap_config(email_addr)
            conn = self.connect_imap(config)
            
            # Buscar emails de los últimos 2 minutos
            date_since = (datetime.now() - timedelta(minutes=2)).strftime("%d-%b-%Y")
            
            # Buscar emails Disney
            search_criteria = []
            for from_addr in DISNEY_FROM_ADDRESSES:
                search_criteria.append(f'(FROM "{from_addr}" TO "{email_addr}" SINCE {date_since})')
            
            combined_criteria = f'OR {" ".join(search_criteria)}' if len(search_criteria) > 1 else search_criteria[0]
            
            status, messages = conn.search(None, combined_criteria)
            
            if not messages[0]:
                logger.info(f"✅ No se encontraron nuevos emails para {email_addr}")
                self.mark_verification_completed(search_id, False)
                return
            
            # Procesar mensajes recientes
            message_ids = messages[0].split()
            message_ids.reverse()
            
            email_changed = False
            
            for msg_id in message_ids[:5]:  # Solo los 5 más recientes
                try:
                    status, msg_data = conn.fetch(msg_id, '(RFC822)')
                    if not msg_data or not msg_data[0] or not msg_data[0][1]:
                        continue
                        
                    raw_email = msg_data[0][1]
                    email_message = email.message_from_bytes(raw_email)
                    
                    # Extraer cuerpo del mensaje
                    body = self.extract_body(email_message)
                    
                    if not body:
                        continue
                    
                    # Verificar patrones de cambio de email
                    for pattern in self.email_change_patterns:
                        try:
                            regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                            if regex.search(body):
                                email_changed = True
                                logger.warning(f"⚠️ Detectado cambio de email en {email_addr}")
                                break
                        except re.error as e:
                            logger.error(f"Error en regex de cambio: {e}")
                            continue
                    
                    if email_changed:
                        break
                        
                except Exception as e:
                    logger.error(f"Error procesando mensaje de verificación: {e}")
                    continue
            
            if email_changed:
                # Bloquear usuario
                reason = f"Cambio de email detectado en {email_addr}"
                db.block_user(user_id, reason, email_addr)
                
                # Marcar verificación como completada
                self.mark_verification_completed(search_id, True)
                
                # Notificar a todos los administradores
                self.notify_admins_email_change(user_id, email_addr, original_code)
                
                logger.warning(f"🚨 Usuario {user_id} bloqueado por cambio de email en {email_addr}")
            else:
                logger.info(f"✅ No se detectó cambio de email para {email_addr}")
                self.mark_verification_completed(search_id, False)
                
        except Exception as e:
            logger.error(f"❌ Error verificando cambio de email: {e}")
            self.mark_verification_completed(search_id, False)
        finally:
            if conn:
                try:
                    conn.logout()
                except:
                    pass
    
    def mark_verification_completed(self, search_id, email_changed):
        """Marca la verificación como completada"""
        try:
            db.execute_query("""
                UPDATE email_change_verifications 
                SET verified_at = CURRENT_TIMESTAMP, email_changed = %s
                WHERE search_id = %s
            """, (email_changed, search_id))
            
            db.execute_query("""
                UPDATE disney_searches 
                SET verification_completed = TRUE
                WHERE id = %s
            """, (search_id,))
            
        except Exception as e:
            logger.error(f"❌ Error marcando verificación completada: {e}")
    
    def notify_admins_email_change(self, user_id, email_addr, original_code):
        """Notifica SOLO a los super administradores sobre cambio de email por Telegram"""
        try:
            # Obtener información del usuario
            user_info = db.execute_query(
                "SELECT username, first_name FROM users WHERE id = %s",
                (user_id,)
            )
            
            username = "Usuario desconocido"
            if user_info:
                username = user_info[0]['username'] or user_info[0]['first_name'] or f"ID_{user_id}"
            
            # ACTUALIZADO: Usar importación diferida y threading para evitar problemas con asyncio
            def send_notification_thread():
                try:
                    # Importar bot en el thread para evitar problemas de import circular
                    from telegram_bot import bot
                    import asyncio
                    
                    # Crear mensaje sin Markdown para evitar errores de parsing
                    message = (
                        "🚨 ALERTA DE SEGURIDAD\n\n"
                        "⚠️ Usuario bloqueado por cambio de email\n\n"
                        f"👤 Usuario: {username}\n"
                        f"🆔 ID: {user_id}\n"
                        f"📧 Email: {email_addr}\n"
                        f"🏰 Código original: {original_code}\n"
                        f"🕐 Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                        "✅ El usuario ha sido bloqueado automáticamente"
                    )
                    
                    # Función async para enviar el mensaje a todos los super admins
                    async def send_messages():
                        try:
                            # Intentar enviar mensaje si el bot está disponible
                            if hasattr(bot, 'app') and bot.app and hasattr(bot.app, 'bot'):
                                
                                # ACTUALIZADO: Enviar SOLO a super administradores
                                successful_sends = 0
                                for admin_id in SUPER_ADMIN_IDS:
                                    try:
                                        await bot.app.bot.send_message(
                                            chat_id=admin_id,
                                            text=message,
                                            parse_mode=None  # Sin formato para evitar errores
                                        )
                                        successful_sends += 1
                                        logger.info(f"✅ Notificación enviada al super admin {admin_id}")
                                    except Exception as e:
                                        logger.error(f"❌ Error enviando notificación al super admin {admin_id}: {e}")
                                
                                if successful_sends > 0:
                                    logger.info(f"✅ Notificación enviada a {successful_sends}/{len(SUPER_ADMIN_IDS)} super admins sobre bloqueo de usuario {user_id}")
                                else:
                                    logger.warning(f"⚠️ No se pudo enviar notificaciones a ningún super admin - Usuario {user_id} bloqueado")
                            else:
                                logger.warning(f"⚠️ Bot no disponible para notificación - Usuario {user_id} bloqueado")
                        except Exception as e:
                            logger.error(f"❌ Error enviando notificación a super admins: {e}")
                    
                    # Ejecutar la notificación
                    try:
                        # Crear un nuevo loop para este thread
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        loop.run_until_complete(send_messages())
                        loop.close()
                    except Exception as e:
                        logger.error(f"❌ Error ejecutando notificación async: {e}")
                        
                except Exception as e:
                    logger.error(f"❌ Error en thread de notificación: {e}")
            
            # Ejecutar en un thread separado para evitar problemas con asyncio
            notification_thread = threading.Thread(
                target=send_notification_thread,
                daemon=True
            )
            notification_thread.start()
            
            # Log para depuración - ACTUALIZADO: Especificar que va solo a super admins
            logger.warning(f"🚨 NOTIFICACIÓN SUPER ADMINS: Usuario {username} ({user_id}) bloqueado por cambio de email en {email_addr}. Código original: {original_code} - Solo notificado a super administradores")
            
        except Exception as e:
            logger.error(f"❌ Error notificando a los super administradores: {e}")

# Instancia global
disney_searcher = DisneySearcher()
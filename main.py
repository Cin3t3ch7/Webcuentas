import asyncio
import logging
import uvicorn
import threading
import time
import signal
import sys
from telegram_bot import bot
from web_app import app
from database import db
from config import LOG_LEVEL, LOG_FORMAT, SUPER_ADMIN_IDS

# Configurar logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('disney_search.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# Suprimir logs innecesarios
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

class DisneySearchSystem:
    def __init__(self):
        self.shutdown_event = asyncio.Event()
        self.bot_task = None
        self.web_server = None
        self.running = False
        self.maintenance_task = None
        
        # Configurar manejadores de señales
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Maneja las señales de terminación"""
        logger.info(f"🛑 Señal {signum} recibida, iniciando cierre...")
        if not self.shutdown_event.is_set():
            self.shutdown_event.set()
    
    async def start_web_server(self):
        """Inicia el servidor web de forma asíncrona"""
        config = uvicorn.Config(
            app, 
            host="0.0.0.0", 
            port=8000,
            log_level="warning",
            access_log=False,
            loop="asyncio"
        )
        self.web_server = uvicorn.Server(config)
        
        try:
            logger.info("🌐 Iniciando servidor web...")
            await self.web_server.serve()
        except asyncio.CancelledError:
            logger.info("🌐 Servidor web cancelado")
            raise
        except Exception as e:
            logger.error(f"❌ Error en servidor web: {e}")
            raise
    
    async def start_bot(self):
        """Inicia el bot de Telegram"""
        try:
            logger.info("🤖 Iniciando bot de Telegram...")
            await bot.run_with_shutdown(self.shutdown_event)
        except asyncio.CancelledError:
            logger.info("🤖 Bot de Telegram cancelado")
            raise
        except Exception as e:
            logger.error(f"❌ Error en bot: {e}")
            raise
    
    def verify_database_connection(self):
        """Verifica la conexión a la base de datos con información detallada"""
        max_retries = 5
        retry_count = 0
        
        logger.info("🔍 Verificando conexión a la base de datos...")
        
        while retry_count < max_retries:
            try:
                logger.info(f"🔗 Intento de conexión {retry_count + 1}/{max_retries}")
                
                # Verificar conexión básica
                db.execute_query("SELECT 1")
                logger.info("✅ Conexión a PostgreSQL exitosa")
                
                # Verificar estado de salud de la BD
                if db.check_database_health():
                    logger.info("✅ Base de datos en estado saludable")
                else:
                    logger.warning("⚠️ Base de datos requiere atención (pero funcional)")
                
                # Mostrar estadísticas del sistema
                self.show_system_stats()
                
                return True
                
            except Exception as e:
                retry_count += 1
                logger.error(f"❌ Error conectando a PostgreSQL (intento {retry_count}/{max_retries}): {e}")
                
                if retry_count < max_retries:
                    wait_time = min(30, 5 * retry_count)
                    logger.info(f"⏳ Esperando {wait_time}s antes de reintentar...")
                    time.sleep(wait_time)
        
        logger.error("❌ No se pudo establecer conexión a la base de datos")
        return False
    
    def show_system_stats(self):
        """Muestra estadísticas del sistema al iniciar"""
        try:
            stats = db.get_system_stats()
            
            logger.info("📊 ESTADÍSTICAS DEL SISTEMA:")
            logger.info("=" * 40)
            
            # Usuarios
            logger.info(f"👥 Total de usuarios: {stats.get('total_users', 0)}")
            logger.info(f"👑 Super administradores: {stats.get('super_admins', 0)}/{len(SUPER_ADMIN_IDS)}")
            logger.info(f"🛡️ Administradores normales: {stats.get('normal_admins', 0)}")
            logger.info(f"👤 Usuarios normales: {stats.get('normal_users', 0)}")
            logger.info(f"🚫 Usuarios bloqueados: {stats.get('blocked_users', 0)}")
            logger.info(f"🔓 Usuarios con acceso libre: {stats.get('free_access_users', 0)}")
            
            # Configuraciones
            logger.info(f"📧 Emails asignados: {stats.get('total_emails', 0)}")
            logger.info(f"⚙️ Configuraciones IMAP: {stats.get('imap_configs', 0)}")
            logger.info(f"🏰 Búsquedas Disney realizadas: {stats.get('disney_searches', 0)}")
            logger.info(f"🔐 Sesiones web activas: {stats.get('active_sessions', 0)}")
            
            logger.info("=" * 40)
            
            # Verificar administradores sin emails
            if stats.get('normal_admins', 0) > 0:
                admins_without_emails = db.execute_query("""
                    SELECT u.id, u.username, u.first_name 
                    FROM users u
                    LEFT JOIN user_emails ue ON u.id = ue.user_id
                    WHERE u.is_admin = TRUE AND u.id != ALL(%s)
                    GROUP BY u.id, u.username, u.first_name
                    HAVING COUNT(ue.email) = 0
                """, (SUPER_ADMIN_IDS,))
                
                if admins_without_emails:
                    logger.warning(f"⚠️  {len(admins_without_emails)} administradores sin emails asignados:")
                    for admin in admins_without_emails:
                        name = admin['username'] or admin['first_name'] or f"Admin_{admin['id']}"
                        logger.warning(f"   - {name} (ID: {admin['id']})")
                    logger.info("💡 Usa /addadmin <user_id> <email1> [email2...] para asignar emails")
                else:
                    logger.info("✅ Todos los administradores tienen emails asignados")
        
        except Exception as e:
            logger.error(f"❌ Error mostrando estadísticas: {e}")
    
    def cleanup_old_sessions(self):
        """Limpia sesiones expiradas"""
        try:
            result = db.execute_query("""
                UPDATE web_sessions 
                SET is_active = FALSE 
                WHERE expires_at < CURRENT_TIMESTAMP AND is_active = TRUE
            """)
            
            if result > 0:
                logger.info(f"🧹 {result} sesiones expiradas limpiadas")
        except Exception as e:
            logger.error(f"❌ Error limpiando sesiones: {e}")
    
    def cleanup_old_verifications(self):
        """Limpia verificaciones antiguas"""
        try:
            result = db.execute_query("""
                DELETE FROM email_change_verifications 
                WHERE scheduled_at < CURRENT_TIMESTAMP - INTERVAL '24 hours'
            """)
            
            if result > 0:
                logger.info(f"🧹 {result} verificaciones antiguas limpiadas")
        except Exception as e:
            logger.error(f"❌ Error limpiando verificaciones: {e}")
    
    async def maintenance_worker(self):
        """Tarea de mantenimiento periódico"""
        logger.info("🧹 Iniciando tarea de mantenimiento")
        
        while not self.shutdown_event.is_set():
            try:
                # Esperar 1 hora o hasta que se señale el cierre
                await asyncio.wait_for(
                    self.shutdown_event.wait(), 
                    timeout=3600.0
                )
                break  # Si el evento se establece, salir del bucle
            except asyncio.TimeoutError:
                # Timeout normal cada hora
                if not self.shutdown_event.is_set():
                    logger.info("🧹 Ejecutando mantenimiento periódico...")
                    self.cleanup_old_sessions()
                    self.cleanup_old_verifications()
            except Exception as e:
                logger.error(f"❌ Error en tarea de mantenimiento: {e}")
                await asyncio.sleep(300)  # Esperar 5 minutos si hay error
        
        logger.info("🧹 Tarea de mantenimiento finalizada")
    
    async def run(self):
        """Ejecuta el sistema completo"""
        try:
            logger.info("🚀 Iniciando Disney Search Pro System...")
            logger.info(f"👑 Super Administradores configurados: {len(SUPER_ADMIN_IDS)}")
            for i, admin_id in enumerate(SUPER_ADMIN_IDS, 1):
                logger.info(f"   {i}. ID: {admin_id}")
            
            # Verificar conexión a base de datos (incluye auto-configuración)
            if not self.verify_database_connection():
                logger.error("❌ No se pudo conectar a la base de datos. Terminando...")
                return False
            
            # Limpiar datos antiguos
            logger.info("🧹 Ejecutando limpieza inicial...")
            self.cleanup_old_sessions()
            self.cleanup_old_verifications()
            
            self.running = True
            
            # Crear tareas principales
            tasks = []
            
            # Tarea del servidor web
            web_task = asyncio.create_task(
                self.start_web_server(),
                name="web_server"
            )
            tasks.append(web_task)
            
            # Tarea del bot de Telegram
            self.bot_task = asyncio.create_task(
                self.start_bot(),
                name="telegram_bot"
            )
            tasks.append(self.bot_task)
            
            # Tarea de mantenimiento
            self.maintenance_task = asyncio.create_task(
                self.maintenance_worker(),
                name="maintenance"
            )
            tasks.append(self.maintenance_task)
            
            logger.info("✅ Sistema iniciado completamente")
            logger.info("🌐 Servidor web: http://localhost:8000")
            logger.info("🤖 Bot de Telegram: Activo")
            logger.info("🧹 Mantenimiento automático: Activo")
            logger.info("🔧 Auto-configuración de BD: Aplicada")
            
            # Esperar hasta que se complete alguna tarea o se solicite cierre
            try:
                done, pending = await asyncio.wait(
                    tasks,
                    return_when=asyncio.FIRST_COMPLETED
                )
                
                # Si no es un cierre programado, algo falló
                if not self.shutdown_event.is_set():
                    logger.warning("⚠️ Una tarea terminó inesperadamente")
                    # Revisar qué tarea falló
                    for task in done:
                        if task.exception():
                            logger.error(f"❌ Tarea {task.get_name()} falló: {task.exception()}")
                
            except KeyboardInterrupt:
                logger.info("🛑 Interrupción por teclado detectada")
                self.shutdown_event.set()
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error crítico en sistema: {e}")
            return False
        finally:
            await self.shutdown()
    
    async def shutdown(self):
        """Cierra el sistema de forma ordenada"""
        if not self.running:
            return
        
        logger.info("🛑 Iniciando cierre del sistema...")
        
        self.running = False
        self.shutdown_event.set()
        
        # Lista de tareas a cancelar
        tasks_to_cancel = []
        
        if self.bot_task and not self.bot_task.done():
            tasks_to_cancel.append(self.bot_task)
        
        if self.maintenance_task and not self.maintenance_task.done():
            tasks_to_cancel.append(self.maintenance_task)
        
        # Cerrar servidor web
        if self.web_server:
            logger.info("🌐 Cerrando servidor web...")
            self.web_server.should_exit = True
        
        # Cancelar tareas restantes
        if tasks_to_cancel:
            logger.info(f"🔄 Cancelando {len(tasks_to_cancel)} tareas...")
            
            for task in tasks_to_cancel:
                if not task.done():
                    task.cancel()
            
            # Esperar a que las tareas se cancelen (máximo 5 segundos)
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks_to_cancel, return_exceptions=True),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                logger.warning("⚠️ Algunas tareas no se cerraron en el tiempo esperado")
            except Exception as e:
                logger.error(f"❌ Error durante el cierre: {e}")
        
        # Pequeña pausa para permitir que el logging se complete
        await asyncio.sleep(0.5)
        
        logger.info("✅ Sistema cerrado correctamente")

async def main():
    """Función principal"""
    system = DisneySearchSystem()
    
    try:
        success = await system.run()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        logger.info("🛑 Sistema detenido por usuario")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Error fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("🏰 Disney Search Pro - Sistema Completo con Auto-Configuración")
    print("=" * 60)
    print("✨ Características:")
    print("   🔧 Auto-reparación de base de datos")
    print("   🛡️ Restricciones automáticas para administradores")
    print("   👑 Configuración automática de super administradores")
    print("   🌐 Interfaz web en puerto 8000")
    print("   🤖 Bot de Telegram integrado")
    print("   🧹 Mantenimiento automático")
    print()
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Sistema detenido por usuario")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error fatal al iniciar: {e}")
        sys.exit(1)
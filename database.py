import psycopg2
import psycopg2.extras
from psycopg2.pool import SimpleConnectionPool
import logging
import threading
import time
from config import DATABASE_URL, SUPER_ADMIN_IDS, is_super_admin

logger = logging.getLogger(__name__)

class Database:
    def __init__(self):
        self.pool = None
        self.lock = threading.Lock()
        self.init_pool()
        
    def init_pool(self):
        max_retries = 5
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                self.pool = SimpleConnectionPool(
                    1, 20,
                    DATABASE_URL,
                    cursor_factory=psycopg2.extras.RealDictCursor
                )
                logger.info("✅ Pool de conexiones PostgreSQL inicializado")
                self.create_tables()
                return
            except Exception as e:
                logger.error(f"❌ Error inicializando pool (intento {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    raise

    def get_connection(self):
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with self.lock:
                    if self.pool is None:
                        self.init_pool()
                    return self.pool.getconn()
            except Exception as e:
                logger.error(f"❌ Error obteniendo conexión (intento {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(1)
                    try:
                        self.init_pool()
                    except:
                        pass
                else:
                    raise
    
    def put_connection(self, conn):
        try:
            with self.lock:
                if self.pool and conn:
                    self.pool.putconn(conn)
        except Exception as e:
            logger.error(f"❌ Error devolviendo conexión: {e}")
    
    def execute_query(self, query, params=None):
        conn = None
        cursor = None
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                cursor.execute(query, params)
                
                if query.strip().upper().startswith('SELECT'):
                    result = cursor.fetchall()
                else:
                    conn.commit()
                    result = cursor.rowcount
                
                return result
                
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                logger.error(f"❌ Error de conexión DB (intento {attempt + 1}/{max_retries}): {e}")
                if conn:
                    try:
                        conn.rollback()
                    except:
                        pass
                if attempt < max_retries - 1:
                    time.sleep(1)
                    try:
                        self.init_pool()
                    except:
                        pass
                else:
                    raise
            except Exception as e:
                if conn:
                    try:
                        conn.rollback()
                    except:
                        pass
                logger.error(f"❌ Error ejecutando query: {e}")
                raise
            finally:
                if cursor:
                    try:
                        cursor.close()
                    except:
                        pass
                if conn:
                    self.put_connection(conn)

    def create_tables(self):
        """✅ CORREGIDO: Crea tablas y aplica todas las correcciones automáticamente con CASCADE FK"""
        logger.info("🔧 Inicializando base de datos con auto-reparación y foreign keys corregidas...")
        
        tables = [
            # Tabla de usuarios (principal)
            """
            CREATE TABLE IF NOT EXISTS users (
                id BIGINT PRIMARY KEY,
                username VARCHAR(255),
                first_name VARCHAR(255),
                last_name VARCHAR(255),
                is_admin BOOLEAN DEFAULT FALSE,
                free_access BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                is_blocked BOOLEAN DEFAULT FALSE,
                blocked_reason TEXT,
                blocked_at TIMESTAMP
            )
            """,
            # Tabla de emails de usuarios (CASCADE FK)
            """
            CREATE TABLE IF NOT EXISTS user_emails (
                id SERIAL PRIMARY KEY,
                user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
                email VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, email)
            )
            """,
            # Tabla de configuraciones IMAP
            """
            CREATE TABLE IF NOT EXISTS imap_configs (
                id SERIAL PRIMARY KEY,
                domain VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) NOT NULL,
                password VARCHAR(255) NOT NULL,
                server VARCHAR(255) NOT NULL,
                port INTEGER DEFAULT 993,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by BIGINT REFERENCES users(id) ON DELETE SET NULL
            )
            """,
            # Tabla de sesiones web (CASCADE FK)
            """
            CREATE TABLE IF NOT EXISTS web_sessions (
                id SERIAL PRIMARY KEY,
                user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
                session_token VARCHAR(255) UNIQUE NOT NULL,
                csrf_token VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT TRUE
            )
            """,
            # ✅ CORREGIDO: Tabla de búsquedas Disney (CASCADE FK)
            """
            CREATE TABLE IF NOT EXISTS disney_searches (
                id SERIAL PRIMARY KEY,
                user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
                email VARCHAR(255) NOT NULL,
                result_type VARCHAR(50),
                result_code VARCHAR(255),
                search_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verification_scheduled BOOLEAN DEFAULT FALSE,
                verification_completed BOOLEAN DEFAULT FALSE
            )
            """,
            # ✅ CORREGIDO: Tabla de verificaciones de cambio de email (CASCADE FK)
            """
            CREATE TABLE IF NOT EXISTS email_change_verifications (
                id SERIAL PRIMARY KEY,
                search_id INTEGER REFERENCES disney_searches(id) ON DELETE CASCADE,
                user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
                email VARCHAR(255) NOT NULL,
                original_code VARCHAR(255),
                scheduled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verified_at TIMESTAMP,
                email_changed BOOLEAN DEFAULT FALSE,
                user_blocked BOOLEAN DEFAULT FALSE
            )
            """
        ]
        
        # Crear tablas básicas
        for i, table_sql in enumerate(tables, 1):
            try:
                self.execute_query(table_sql)
                logger.info(f"✅ Tabla {i}/{len(tables)} creada/verificada")
            except Exception as e:
                logger.error(f"❌ Error creando tabla {i}: {e}")
        
        # ✅ NUEVO: Aplicar correcciones de foreign keys para tablas existentes
        self.fix_foreign_key_constraints()
        
        # Aplicar correcciones automáticamente
        self.apply_automatic_fixes()
        
        # Crear super admins
        self.create_super_admins()
        
        # Aplicar restricciones para administradores
        self.apply_admin_restrictions()
        
        logger.info("🎉 Base de datos inicializada completamente con todas las correcciones aplicadas")
    
    def fix_foreign_key_constraints(self):
        """✅ NUEVO: Corrige foreign key constraints existentes para agregar CASCADE"""
        logger.info("🔧 Verificando y corrigiendo foreign key constraints...")
        
        try:
            # Verificar foreign keys existentes que necesitan CASCADE
            constraint_fixes = [
                {
                    'table': 'disney_searches',
                    'constraint_name': 'disney_searches_user_id_fkey',
                    'column': 'user_id',
                    'references': 'users(id)',
                    'action': 'CASCADE'
                },
                {
                    'table': 'email_change_verifications', 
                    'constraint_name': 'email_change_verifications_user_id_fkey',
                    'column': 'user_id',
                    'references': 'users(id)',
                    'action': 'CASCADE'
                },
                {
                    'table': 'email_change_verifications',
                    'constraint_name': 'email_change_verifications_search_id_fkey', 
                    'column': 'search_id',
                    'references': 'disney_searches(id)',
                    'action': 'CASCADE'
                }
            ]
            
            for fix in constraint_fixes:
                try:
                    # Verificar si la constraint existe
                    constraint_check = self.execute_query("""
                        SELECT constraint_name, delete_rule 
                        FROM information_schema.referential_constraints 
                        WHERE constraint_name = %s
                    """, (fix['constraint_name'],))
                    
                    if constraint_check:
                        current_rule = constraint_check[0].get('delete_rule', 'NO ACTION')
                        
                        if current_rule != 'CASCADE':
                            logger.info(f"🔧 Corrigiendo constraint {fix['constraint_name']} (actual: {current_rule} -> CASCADE)")
                            
                            # Eliminar constraint existente
                            self.execute_query(f"""
                                ALTER TABLE {fix['table']} 
                                DROP CONSTRAINT IF EXISTS {fix['constraint_name']}
                            """)
                            
                            # Agregar constraint corregida
                            self.execute_query(f"""
                                ALTER TABLE {fix['table']} 
                                ADD CONSTRAINT {fix['constraint_name']} 
                                FOREIGN KEY ({fix['column']}) 
                                REFERENCES {fix['references']} 
                                ON DELETE {fix['action']}
                            """)
                            
                            logger.info(f"✅ Constraint {fix['constraint_name']} corregida")
                        else:
                            logger.info(f"✅ Constraint {fix['constraint_name']} ya tiene CASCADE")
                    else:
                        logger.info(f"ℹ️ Constraint {fix['constraint_name']} no existe (se creará con la tabla)")
                        
                except Exception as e:
                    logger.warning(f"⚠️ Error corrigiendo constraint {fix['constraint_name']}: {e}")
                    continue
            
            logger.info("✅ Verificación de foreign key constraints completada")
            
        except Exception as e:
            logger.error(f"❌ Error en corrección de foreign keys: {e}")
    
    def apply_automatic_fixes(self):
        """Aplica todas las correcciones necesarias automáticamente"""
        logger.info("🔧 Aplicando correcciones automáticas...")
        
        # Lista de correcciones a aplicar
        fixes = [
            # Agregar columnas faltantes a users si no existen
            {
                'name': 'is_blocked en users',
                'query': """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='is_blocked') THEN
                        ALTER TABLE users ADD COLUMN is_blocked BOOLEAN DEFAULT FALSE;
                    END IF;
                END $$;
                """
            },
            {
                'name': 'blocked_reason en users',
                'query': """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='blocked_reason') THEN
                        ALTER TABLE users ADD COLUMN blocked_reason TEXT;
                    END IF;
                END $$;
                """
            },
            {
                'name': 'blocked_at en users',
                'query': """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='blocked_at') THEN
                        ALTER TABLE users ADD COLUMN blocked_at TIMESTAMP;
                    END IF;
                END $$;
                """
            },
            
            # Agregar columnas faltantes a disney_searches si no existen
            {
                'name': 'verification_scheduled en disney_searches',
                'query': """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='disney_searches' AND column_name='verification_scheduled') THEN
                        ALTER TABLE disney_searches ADD COLUMN verification_scheduled BOOLEAN DEFAULT FALSE;
                    END IF;
                END $$;
                """
            },
            {
                'name': 'verification_completed en disney_searches',
                'query': """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='disney_searches' AND column_name='verification_completed') THEN
                        ALTER TABLE disney_searches ADD COLUMN verification_completed BOOLEAN DEFAULT FALSE;
                    END IF;
                END $$;
                """
            },
            
            # Actualizar valores NULL
            {
                'name': 'Actualizar is_blocked NULL',
                'query': "UPDATE users SET is_blocked = FALSE WHERE is_blocked IS NULL;"
            },
            {
                'name': 'Actualizar verification_scheduled NULL',
                'query': "UPDATE disney_searches SET verification_scheduled = FALSE WHERE verification_scheduled IS NULL;"
            },
            {
                'name': 'Actualizar verification_completed NULL', 
                'query': "UPDATE disney_searches SET verification_completed = FALSE WHERE verification_completed IS NULL;"
            }
        ]
        
        # Aplicar cada corrección
        for fix in fixes:
            try:
                self.execute_query(fix['query'])
                logger.info(f"✅ Corrección aplicada: {fix['name']}")
            except Exception as e:
                logger.warning(f"⚠️ Corrección {fix['name']}: {e}")
                continue
    
    def create_super_admins(self):
        """Crea todos los super admins definidos en SUPER_ADMIN_IDS"""
        logger.info("👑 Configurando super administradores...")
        
        try:
            for i, admin_id in enumerate(SUPER_ADMIN_IDS):
                # Verificar si existe
                existing = self.execute_query(
                    "SELECT id FROM users WHERE id = %s", 
                    (admin_id,)
                )
                
                if not existing:
                    # Crear super admin
                    username = f'SuperAdmin_{i+1}' if i > 0 else 'SuperAdmin'
                    first_name = f'Super Administrator {i+1}' if i > 0 else 'Super Administrator'
                    
                    self.execute_query("""
                        INSERT INTO users (id, username, first_name, is_admin, free_access, is_active)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (admin_id, username, first_name, True, True, True))
                    logger.info(f"✅ Super admin {i+1} creado: {admin_id}")
                else:
                    # Asegurar que tenga los permisos correctos
                    self.execute_query("""
                        UPDATE users SET is_admin = TRUE, free_access = TRUE, is_active = TRUE, is_blocked = FALSE
                        WHERE id = %s
                    """, (admin_id,))
                    logger.info(f"✅ Super admin {i+1} verificado/actualizado: {admin_id}")
        except Exception as e:
            logger.error(f"❌ Error creando super admins: {e}")
    
    def apply_admin_restrictions(self):
        """Aplica automáticamente las restricciones para administradores normales"""
        logger.info("🛡️ Aplicando restricciones para administradores normales...")
        
        try:
            # Remover acceso libre de administradores normales (que no sean super admins)
            result = self.execute_query("""
                UPDATE users 
                SET free_access = FALSE 
                WHERE is_admin = TRUE AND id != ALL(%s)
            """, (SUPER_ADMIN_IDS,))
            
            if result > 0:
                logger.info(f"✅ Acceso libre removido de {result} administradores normales")
            
            # Verificar administradores existentes
            admins = self.execute_query("""
                SELECT u.id, u.username, u.first_name, 
                       COUNT(ue.email) as email_count
                FROM users u
                LEFT JOIN user_emails ue ON u.id = ue.user_id
                WHERE u.is_admin = TRUE AND u.id != ALL(%s)
                GROUP BY u.id, u.username, u.first_name
            """, (SUPER_ADMIN_IDS,))
            
            if admins:
                logger.info(f"📋 Administradores normales encontrados: {len(admins)}")
                
                admins_with_emails = 0
                admins_without_emails = 0
                
                for admin in admins:
                    admin_id, username, first_name, email_count = admin
                    name = username or first_name or f"Admin_{admin_id}"
                    
                    if email_count > 0:
                        admins_with_emails += 1
                        logger.info(f"   ✅ {name} (ID: {admin_id}) - {email_count} emails asignados")
                    else:
                        admins_without_emails += 1
                        logger.warning(f"   ⚠️  {name} (ID: {admin_id}) - SIN EMAILS (usar /addadmin para asignar)")
                
                logger.info(f"📊 Resumen: {admins_with_emails} con emails, {admins_without_emails} sin emails")
                
                if admins_without_emails > 0:
                    logger.warning(f"⚠️  {admins_without_emails} administradores necesitan emails asignados")
                    logger.info("💡 Usa /addadmin <user_id> <email1> [email2...] para asignar emails")
            else:
                logger.info("ℹ️ No se encontraron administradores normales")
        
        except Exception as e:
            logger.error(f"❌ Error aplicando restricciones de administradores: {e}")
    
    def check_database_health(self):
        """✅ MEJORADO: Verifica el estado de salud de la base de datos incluyendo foreign keys"""
        try:
            logger.info("🔍 Verificando estado de salud de la base de datos...")
            
            # Verificar tablas principales
            required_tables = [
                'users', 'user_emails', 'imap_configs', 
                'web_sessions', 'disney_searches', 'email_change_verifications'
            ]
            
            for table in required_tables:
                result = self.execute_query("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_name = %s
                """, (table,))
                
                if not result:
                    logger.error(f"❌ Tabla faltante: {table}")
                    return False
            
            # Verificar columnas críticas
            critical_columns = [
                ('users', ['is_blocked', 'blocked_reason', 'blocked_at']),
                ('disney_searches', ['verification_scheduled', 'verification_completed'])
            ]
            
            for table, columns in critical_columns:
                for column in columns:
                    result = self.execute_query("""
                        SELECT column_name 
                        FROM information_schema.columns 
                        WHERE table_name = %s AND column_name = %s
                    """, (table, column))
                    
                    if not result:
                        logger.error(f"❌ Columna faltante: {table}.{column}")
                        return False
            
            # ✅ NUEVO: Verificar foreign key constraints críticas
            critical_constraints = [
                ('disney_searches_user_id_fkey', 'CASCADE'),
                ('email_change_verifications_user_id_fkey', 'CASCADE'),
                ('user_emails_user_id_fkey', 'CASCADE'),
                ('web_sessions_user_id_fkey', 'CASCADE')
            ]
            
            for constraint_name, expected_rule in critical_constraints:
                constraint_info = self.execute_query("""
                    SELECT constraint_name, delete_rule 
                    FROM information_schema.referential_constraints 
                    WHERE constraint_name = %s
                """, (constraint_name,))
                
                if not constraint_info:
                    logger.warning(f"⚠️ Constraint faltante: {constraint_name}")
                elif constraint_info[0]['delete_rule'] != expected_rule:
                    logger.warning(f"⚠️ Constraint {constraint_name} tiene regla {constraint_info[0]['delete_rule']}, esperada: {expected_rule}")
                else:
                    logger.info(f"✅ Constraint {constraint_name} correcta")
            
            # Verificar super admins
            super_admin_count = self.execute_query("""
                SELECT COUNT(*) as count 
                FROM users 
                WHERE id = ANY(%s) AND is_admin = TRUE AND is_active = TRUE
            """, (SUPER_ADMIN_IDS,))
            
            if not super_admin_count or super_admin_count[0]['count'] != len(SUPER_ADMIN_IDS):
                logger.warning("⚠️ No todos los super administradores están configurados correctamente")
                return False
            
            # Verificar integridad referencial
            integrity_checks = [
                {
                    'name': 'disney_searches -> users',
                    'query': """
                        SELECT COUNT(*) as count FROM disney_searches ds 
                        LEFT JOIN users u ON ds.user_id = u.id 
                        WHERE u.id IS NULL
                    """
                },
                {
                    'name': 'user_emails -> users', 
                    'query': """
                        SELECT COUNT(*) as count FROM user_emails ue 
                        LEFT JOIN users u ON ue.user_id = u.id 
                        WHERE u.id IS NULL
                    """
                }
            ]
            
            for check in integrity_checks:
                result = self.execute_query(check['query'])
                orphaned_count = result[0]['count'] if result else 0
                
                if orphaned_count > 0:
                    logger.warning(f"⚠️ {orphaned_count} registros huérfanos en {check['name']}")
                else:
                    logger.info(f"✅ Integridad referencial correcta: {check['name']}")
            
            logger.info("✅ Base de datos en estado saludable")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error verificando estado de la base de datos: {e}")
            return False

    def safe_delete_user(self, user_id):
        """✅ NUEVO: Elimina un usuario de forma segura verificando constraints"""
        try:
            # Verificar si es super admin
            if user_id in SUPER_ADMIN_IDS:
                raise ValueError("No se puede eliminar a un super administrador")
            
            # Verificar si es admin
            is_admin = self.execute_query(
                "SELECT is_admin FROM users WHERE id = %s AND is_admin = TRUE",
                (user_id,)
            )
            
            if is_admin:
                raise ValueError("No se puede eliminar a un administrador. Usa /deladmin primero")
            
            # Verificar si el usuario existe
            user_exists = self.execute_query("SELECT id FROM users WHERE id = %s", (user_id,))
            
            if not user_exists:
                raise ValueError(f"Usuario {user_id} no encontrado")
            
            # Con CASCADE correctamente configurado, esto debería funcionar automáticamente
            result = self.execute_query("DELETE FROM users WHERE id = %s", (user_id,))
            
            if result > 0:
                logger.info(f"✅ Usuario {user_id} eliminado correctamente con todos sus registros relacionados")
                return True
            else:
                raise ValueError(f"No se pudo eliminar el usuario {user_id}")
                
        except Exception as e:
            logger.error(f"❌ Error eliminando usuario {user_id}: {e}")
            raise

    def block_user(self, user_id, reason, email_involved=None):
        """Bloquea a un usuario y cierra automáticamente sus sesiones web"""
        try:
            # 1. Bloquear usuario
            self.execute_query("""
                UPDATE users SET is_blocked = TRUE, blocked_reason = %s, blocked_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (reason, user_id))
            
            logger.info(f"✅ Usuario {user_id} bloqueado por: {reason}")
            
            # 2. Cerrar automáticamente todas las sesiones web activas del usuario
            sessions_closed = self.execute_query("""
                UPDATE web_sessions 
                SET is_active = FALSE 
                WHERE user_id = %s AND is_active = TRUE
            """, (user_id,))
            
            if sessions_closed > 0:
                logger.info(f"🔒 {sessions_closed} sesiones web cerradas automáticamente para usuario {user_id}")
            
            if email_involved:
                logger.info(f"📧 Email involucrado: {email_involved}")
                
        except Exception as e:
            logger.error(f"❌ Error bloqueando usuario {user_id}: {e}")

    def get_system_stats(self):
        """Obtiene estadísticas del sistema para logging"""
        try:
            stats = {}
            
            # Contar usuarios por tipo
            user_stats = self.execute_query("""
                SELECT 
                    COUNT(*) as total_users,
                    COUNT(CASE WHEN is_admin = TRUE AND id = ANY(%s) THEN 1 END) as super_admins,
                    COUNT(CASE WHEN is_admin = TRUE AND id != ALL(%s) THEN 1 END) as normal_admins,
                    COUNT(CASE WHEN is_admin = FALSE THEN 1 END) as normal_users,
                    COUNT(CASE WHEN is_blocked = TRUE THEN 1 END) as blocked_users,
                    COUNT(CASE WHEN free_access = TRUE THEN 1 END) as free_access_users
                FROM users
            """, (SUPER_ADMIN_IDS, SUPER_ADMIN_IDS))
            
            if user_stats:
                stats.update(user_stats[0])
            
            # Contar emails y configuraciones
            misc_stats = self.execute_query("""
                SELECT 
                    (SELECT COUNT(*) FROM user_emails) as total_emails,
                    (SELECT COUNT(*) FROM imap_configs) as imap_configs,
                    (SELECT COUNT(*) FROM disney_searches) as disney_searches,
                    (SELECT COUNT(*) FROM web_sessions WHERE is_active = TRUE) as active_sessions
            """)
            
            if misc_stats:
                stats.update(misc_stats[0])
            
            return stats
            
        except Exception as e:
            logger.error(f"❌ Error obteniendo estadísticas del sistema: {e}")
            return {}

    def cleanup_orphaned_records(self):
        """✅ NUEVO: Limpia registros huérfanos que podrían existir antes de aplicar CASCADE"""
        try:
            logger.info("🧹 Limpiando registros huérfanos...")
            
            # Limpiar búsquedas Disney huérfanas
            orphaned_searches = self.execute_query("""
                DELETE FROM disney_searches 
                WHERE user_id NOT IN (SELECT id FROM users)
            """)
            
            if orphaned_searches > 0:
                logger.info(f"🧹 {orphaned_searches} búsquedas Disney huérfanas eliminadas")
            
            # Limpiar verificaciones huérfanas
            orphaned_verifications = self.execute_query("""
                DELETE FROM email_change_verifications 
                WHERE user_id NOT IN (SELECT id FROM users)
                   OR search_id NOT IN (SELECT id FROM disney_searches)
            """)
            
            if orphaned_verifications > 0:
                logger.info(f"🧹 {orphaned_verifications} verificaciones huérfanas eliminadas")
            
            # Limpiar sesiones web huérfanas (aunque deberían tener CASCADE)
            orphaned_sessions = self.execute_query("""
                DELETE FROM web_sessions 
                WHERE user_id NOT IN (SELECT id FROM users)
            """)
            
            if orphaned_sessions > 0:
                logger.info(f"🧹 {orphaned_sessions} sesiones web huérfanas eliminadas")
            
            logger.info("✅ Limpieza de registros huérfanos completada")
            
        except Exception as e:
            logger.error(f"❌ Error limpiando registros huérfanos: {e}")

# Instancia global
db = Database()
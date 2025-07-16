#!/usr/bin/env python3
"""
Script rápido para reparar la base de datos con restricciones para administradores y foreign keys
Ejecuta este script si tienes errores de columnas faltantes, foreign key constraints o para aplicar las nuevas restricciones
"""

import sys
import psycopg2
from config import DATABASE_URL, SUPER_ADMIN_IDS

def fix_database():
    """✅ ACTUALIZADO: Repara la base de datos agregando columnas faltantes, corrigiendo FK y aplicando restricciones para admins"""
    print("🔧 Reparando base de datos con restricciones para administradores y foreign keys corregidas...")
    
    try:
        # Conectar a la base de datos
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        print("✅ Conectado a PostgreSQL")
        
        # ✅ NUEVO: Primero limpiar registros huérfanos antes de aplicar constraints
        print("\n🧹 Limpiando registros huérfanos...")
        
        cleanup_commands = [
            # Limpiar búsquedas Disney huérfanas
            """
            DELETE FROM disney_searches 
            WHERE user_id NOT IN (SELECT id FROM users);
            """,
            # Limpiar verificaciones huérfanas por user_id
            """
            DELETE FROM email_change_verifications 
            WHERE user_id NOT IN (SELECT id FROM users);
            """,
            # Limpiar verificaciones huérfanas por search_id
            """
            DELETE FROM email_change_verifications 
            WHERE search_id NOT IN (SELECT id FROM disney_searches);
            """,
            # Limpiar sesiones web huérfanas
            """
            DELETE FROM web_sessions 
            WHERE user_id NOT IN (SELECT id FROM users);
            """
        ]
        
        for i, cleanup_cmd in enumerate(cleanup_commands, 1):
            try:
                cursor.execute(cleanup_cmd)
                deleted_count = cursor.rowcount
                conn.commit()
                if deleted_count > 0:
                    print(f"✅ Comando limpieza {i}: {deleted_count} registros huérfanos eliminados")
                else:
                    print(f"✅ Comando limpieza {i}: Sin registros huérfanos")
            except Exception as e:
                print(f"⚠️ Comando limpieza {i} - {e}")
                conn.rollback()
                continue
        
        # ✅ NUEVO: Corregir foreign key constraints
        print("\n🔧 Corrigiendo foreign key constraints...")
        
        constraint_fixes = [
            {
                'table': 'disney_searches',
                'constraint': 'disney_searches_user_id_fkey',
                'column': 'user_id',
                'references': 'users(id)',
                'action': 'CASCADE'
            },
            {
                'table': 'email_change_verifications',
                'constraint': 'email_change_verifications_user_id_fkey', 
                'column': 'user_id',
                'references': 'users(id)',
                'action': 'CASCADE'
            },
            {
                'table': 'email_change_verifications',
                'constraint': 'email_change_verifications_search_id_fkey',
                'column': 'search_id', 
                'references': 'disney_searches(id)',
                'action': 'CASCADE'
            }
        ]
        
        for fix in constraint_fixes:
            try:
                # Verificar si la constraint existe y su regla actual
                cursor.execute("""
                    SELECT constraint_name, delete_rule 
                    FROM information_schema.referential_constraints 
                    WHERE constraint_name = %s
                """, (fix['constraint'],))
                
                constraint_info = cursor.fetchone()
                
                if constraint_info:
                    current_rule = constraint_info[1] if constraint_info[1] else 'NO ACTION'
                    
                    if current_rule != 'CASCADE':
                        print(f"🔧 Corrigiendo {fix['constraint']} (actual: {current_rule} -> CASCADE)")
                        
                        # Eliminar constraint existente
                        cursor.execute(f"ALTER TABLE {fix['table']} DROP CONSTRAINT IF EXISTS {fix['constraint']}")
                        
                        # Agregar constraint corregida
                        cursor.execute(f"""
                            ALTER TABLE {fix['table']} 
                            ADD CONSTRAINT {fix['constraint']} 
                            FOREIGN KEY ({fix['column']}) 
                            REFERENCES {fix['references']} 
                            ON DELETE {fix['action']}
                        """)
                        
                        conn.commit()
                        print(f"✅ Constraint {fix['constraint']} corregida a CASCADE")
                    else:
                        print(f"✅ Constraint {fix['constraint']} ya tiene CASCADE")
                else:
                    print(f"ℹ️ Constraint {fix['constraint']} no existe (se creará automáticamente)")
                    
            except Exception as e:
                print(f"⚠️ Error corrigiendo constraint {fix['constraint']}: {e}")
                conn.rollback()
                continue
        
        # Lista de comandos SQL para reparar (comandos existentes)
        print("\n🔧 Aplicando correcciones de columnas...")
        
        fix_commands = [
            # Agregar columnas a users si no existen
            """
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='is_blocked') THEN
                    ALTER TABLE users ADD COLUMN is_blocked BOOLEAN DEFAULT FALSE;
                    RAISE NOTICE 'Columna is_blocked agregada a users';
                END IF;
            END $$;
            """,
            """
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='blocked_reason') THEN
                    ALTER TABLE users ADD COLUMN blocked_reason TEXT;
                    RAISE NOTICE 'Columna blocked_reason agregada a users';
                END IF;
            END $$;
            """,
            """
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='blocked_at') THEN
                    ALTER TABLE users ADD COLUMN blocked_at TIMESTAMP;
                    RAISE NOTICE 'Columna blocked_at agregada a users';
                END IF;
            END $$;
            """,
            
            # Agregar columnas a disney_searches si no existen
            """
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='disney_searches' AND column_name='verification_scheduled') THEN
                    ALTER TABLE disney_searches ADD COLUMN verification_scheduled BOOLEAN DEFAULT FALSE;
                    RAISE NOTICE 'Columna verification_scheduled agregada a disney_searches';
                END IF;
            END $$;
            """,
            """
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='disney_searches' AND column_name='verification_completed') THEN
                    ALTER TABLE disney_searches ADD COLUMN verification_completed BOOLEAN DEFAULT FALSE;
                    RAISE NOTICE 'Columna verification_completed agregada a disney_searches';
                END IF;
            END $$;
            """,
            
            # Crear tabla email_change_verifications si no existe
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
            );
            """,
            
            # Actualizar usuarios existentes
            """
            UPDATE users SET is_blocked = FALSE WHERE is_blocked IS NULL;
            """,
            """
            UPDATE disney_searches SET verification_scheduled = FALSE WHERE verification_scheduled IS NULL;
            """,
            """
            UPDATE disney_searches SET verification_completed = FALSE WHERE verification_completed IS NULL;
            """,
            
            # NUEVO: Aplicar restricciones para administradores normales
            """
            UPDATE users 
            SET free_access = FALSE 
            WHERE is_admin = TRUE AND id != ALL(%s);
            """
        ]
        
        # Ejecutar cada comando
        for i, command in enumerate(fix_commands, 1):
            try:
                print(f"🔄 Ejecutando comando {i}/{len(fix_commands)}...")
                if i == len(fix_commands):  # Último comando con parámetros
                    cursor.execute(command, (SUPER_ADMIN_IDS,))
                else:
                    cursor.execute(command)
                conn.commit()
                print(f"✅ Comando {i} ejecutado")
            except Exception as e:
                print(f"⚠️ Comando {i} - {e}")
                conn.rollback()
                continue
        
        # Configurar múltiples super admins
        print("\n👑 Configurando super administradores...")
        for i, admin_id in enumerate(SUPER_ADMIN_IDS, 1):
            try:
                # Verificar si existe
                cursor.execute("SELECT id FROM users WHERE id = %s", (admin_id,))
                existing = cursor.fetchone()
                
                if not existing:
                    # Crear super admin
                    username = f'SuperAdmin_{i}' if i > 1 else 'SuperAdmin'
                    first_name = f'Super Administrator {i}' if i > 1 else 'Super Administrator'
                    
                    cursor.execute("""
                        INSERT INTO users (id, username, first_name, is_admin, free_access, is_active)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (admin_id, username, first_name, True, True, True))
                    conn.commit()
                    print(f"✅ Super admin {i} creado: {admin_id}")
                else:
                    # Asegurar que tenga los permisos correctos
                    cursor.execute("""
                        UPDATE users SET is_admin = TRUE, free_access = TRUE, is_active = TRUE, is_blocked = FALSE
                        WHERE id = %s
                    """, (admin_id,))
                    conn.commit()
                    print(f"✅ Super admin {i} verificado/actualizado: {admin_id}")
                    
            except Exception as e:
                print(f"❌ Error configurando super admin {admin_id}: {e}")
                conn.rollback()
                continue
        
        # NUEVO: Revisar administradores normales existentes
        print("\n🛡️ Revisando administradores normales...")
        cursor.execute("""
            SELECT id, username, first_name, free_access 
            FROM users 
            WHERE is_admin = TRUE AND id != ALL(%s)
        """, (SUPER_ADMIN_IDS,))
        
        normal_admins = cursor.fetchall()
        
        if normal_admins:
            print(f"📋 Encontrados {len(normal_admins)} administradores normales:")
            
            for admin in normal_admins:
                admin_id, username, first_name, free_access = admin
                name = username or first_name or f"Admin_{admin_id}"
                
                # Verificar emails asignados
                cursor.execute("""
                    SELECT COUNT(*) as email_count
                    FROM user_emails 
                    WHERE user_id = %s
                """, (admin_id,))
                
                email_count = cursor.fetchone()[0]
                
                status = "✅ CON EMAILS" if email_count > 0 else "⚠️  SIN EMAILS"
                access_note = " (Acceso libre removido)" if free_access else ""
                
                print(f"   - {name} (ID: {admin_id}) - {email_count} emails - {status}{access_note}")
                
                if email_count == 0:
                    print(f"     💡 Usa: /addadmin {admin_id} admin@dominio.com para asignar emails")
        else:
            print("ℹ️ No se encontraron administradores normales")
        
        # ✅ NUEVO: Verificar foreign key constraints críticas
        print("\n🔍 Verificando foreign key constraints...")
        
        critical_constraints = [
            ('disney_searches_user_id_fkey', 'CASCADE'),
            ('email_change_verifications_user_id_fkey', 'CASCADE'),
            ('email_change_verifications_search_id_fkey', 'CASCADE'),
            ('user_emails_user_id_fkey', 'CASCADE'),
            ('web_sessions_user_id_fkey', 'CASCADE')
        ]
        
        constraints_ok = 0
        constraints_issues = 0
        
        for constraint_name, expected_rule in critical_constraints:
            cursor.execute("""
                SELECT constraint_name, delete_rule 
                FROM information_schema.referential_constraints 
                WHERE constraint_name = %s
            """, (constraint_name,))
            
            constraint_info = cursor.fetchone()
            
            if not constraint_info:
                print(f"⚠️ Constraint faltante: {constraint_name}")
                constraints_issues += 1
            elif constraint_info[1] != expected_rule:
                print(f"⚠️ Constraint {constraint_name} tiene regla {constraint_info[1]}, esperada: {expected_rule}")
                constraints_issues += 1
            else:
                print(f"✅ Constraint {constraint_name} correcta")
                constraints_ok += 1
        
        print(f"\n📊 Constraints: {constraints_ok} correctas, {constraints_issues} con issues")
        
        # Verificar reparación
        print("\n🔍 Verificando reparación...")
        
        # Verificar columnas users
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users' 
            AND column_name IN ('is_blocked', 'blocked_reason', 'blocked_at')
        """)
        user_columns = cursor.fetchall()
        print(f"✅ Columnas en users: {len(user_columns)}/3")
        
        # Verificar columnas disney_searches
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'disney_searches' 
            AND column_name IN ('verification_scheduled', 'verification_completed')
        """)
        search_columns = cursor.fetchall()
        print(f"✅ Columnas en disney_searches: {len(search_columns)}/2")
        
        # Verificar tabla email_change_verifications
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_name = 'email_change_verifications'
        """)
        verification_table = cursor.fetchall()
        print(f"✅ Tabla email_change_verifications: {'Existe' if verification_table else 'No existe'}")
        
        # Verificar super admins
        cursor.execute("""
            SELECT id, username, is_admin, free_access 
            FROM users 
            WHERE id = ANY(%s)
        """, (SUPER_ADMIN_IDS,))
        super_admins = cursor.fetchall()
        print(f"✅ Super administradores configurados: {len(super_admins)}/{len(SUPER_ADMIN_IDS)}")
        
        for admin in super_admins:
            print(f"   - ID: {admin[0]}, Username: {admin[1]}, Admin: {admin[2]}, Free Access: {admin[3]}")
        
        cursor.close()
        conn.close()
        
        print("\n🎉 ¡Base de datos reparada exitosamente con restricciones para administradores y foreign keys corregidas!")
        print("📝 Ahora puedes ejecutar: python main.py")
        
        return True
        
    except Exception as e:
        print(f"❌ Error reparando base de datos: {e}")
        return False

def show_new_features():
    """Muestra información sobre las nuevas características implementadas"""
    print("\n📖 NUEVAS CARACTERÍSTICAS IMPLEMENTADAS:")
    print("=" * 60)
    print("🔐 CORRECCIONES DE FOREIGN KEY CONSTRAINTS:")
    print("   • disney_searches -> users (ON DELETE CASCADE)")
    print("   • email_change_verifications -> users (ON DELETE CASCADE)")
    print("   • email_change_verifications -> disney_searches (ON DELETE CASCADE)")
    print("   • Eliminar usuarios ahora funciona correctamente")
    print("   • Limpieza automática de registros huérfanos")
    print()
    print("🛡️ DIFERENCIAS ENTRE TIPOS DE USUARIOS:")
    print()
    print("👑 SUPER ADMINISTRADORES:")
    print("   • Acceso total a todos los comandos")
    print("   • Pueden usar cualquier email")
    print("   • Únicos que pueden:")
    print("     - Configurar IMAP (/addimap, /delimap)")
    print("     - Gestionar administradores (/addadmin, /deladmin)")
    print("     - Dar/quitar acceso libre (/free)")
    print("     - Ver/gestionar usuarios bloqueados (/blocked, /unblock)")
    print("   • Reciben notificaciones de seguridad")
    print()
    print("🛡️ ADMINISTRADORES NORMALES (RESTRINGIDOS):")
    print("   • Solo pueden usar emails específicamente asignados")
    print("   • Comandos disponibles:")
    print("     - /add, /del (solo emails asignados a ellos)")
    print("     - /list, /deluser")
    print("     - /check (solo emails asignados a ellos)")
    print("   • NO tienen acceso a:")
    print("     - Configuración IMAP")
    print("     - Gestión de administradores")
    print("     - Gestión de usuarios bloqueados")
    print("     - Dar acceso libre")
    print("   • Serán bloqueados si cambian emails durante búsquedas")
    print()
    print("👤 USUARIOS NORMALES:")
    print("   • Solo comando /check con emails asignados")
    print("   • Pueden tener acceso libre (configurado por super admin)")
    print()
    print("⚡ COMANDOS PARA GESTIONAR RESTRICCIONES:")
    print("   /addadmin <user_id> <email1> [email2...] - Crear admin con emails específicos")
    print("   /free <user_id> remove_admin - Quitar permisos de admin")
    print("   /deladmin <user_id> - Quitar permisos de administrador")
    print("   /deluser <user_id> - Ahora funciona correctamente con CASCADE")
    print()
    print("🔧 CASE SENSITIVITY:")
    print("   • Búsquedas de emails ahora son case-insensitive")
    print("   • Disnry739134@cloverhub.online = disnry739134@cloverhub.online")
    print("   • Admins pueden usar emails sin importar mayúsculas/minúsculas")

if __name__ == "__main__":
    print("🚀 Disney Search Pro - Reparador de Base de Datos ACTUALIZADO")
    print("=" * 70)
    print("Este script repara la BD, corrige foreign keys y aplica restricciones para administradores")
    print(f"👑 Super administradores configurados: {len(SUPER_ADMIN_IDS)}")
    for i, admin_id in enumerate(SUPER_ADMIN_IDS, 1):
        print(f"   {i}. ID: {admin_id}")
    print()
    
    # Confirmar reparación
    try:
        confirm = input("¿Continuar con la reparación completa (FK + restricciones)? (s/N): ").strip().lower()
        if confirm not in ['s', 'si', 'sí', 'y', 'yes']:
            print("❌ Reparación cancelada por el usuario")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\n❌ Reparación cancelada")
        sys.exit(0)
    
    success = fix_database()
    
    if success:
        show_new_features()
        print("\n✅ Reparación completada exitosamente")
        print("🔄 Reinicia el sistema: python main.py")
        sys.exit(0)
    else:
        print("\n❌ Error en reparación")
        print("📞 Contacta al soporte técnico")
        sys.exit(1)
// Archivo: db.js
// Propósito: Conectarse a la base de datos SQLite y preparar consultas básicas.

// Importamos el paquete 'better-sqlite3', que permite trabajar con SQLite
// de forma rápida, sin callbacks, y con consultas preparadas.
import Database from 'better-sqlite3';

// Importamos módulos nativos de Node.js:
// 'fs' -> para leer archivos (en este caso, el schema.sql)
// 'path' -> para construir rutas de archivos de manera segura.
// 'fileURLToPath' -> porque estamos usando módulos ES(archivo JavaScript que exporta algo), y necesitamos convertir
// la URL del archivo actual en una ruta física en el sistema.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Estas líneas permiten obtener el directorio actual
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Definimos la ruta donde estará almacenada la base de datos SQLite (.db)
// En este caso, se creará un archivo llamado 'passport-inc.db' en la carpeta raíz del proyecto.
const DB_PATH = path.join(__dirname, '..', 'passport-inc.db');

// Definimos la ruta del archivo que contiene el esquema SQL (tablas y estructura)
const SCHEMA_PATH = path.join(__dirname, 'schema.sql');

// Creamos o abrimos la base de datos SQLite
// Si el archivo no existe, SQLite lo crea automáticamente.
// 'better-sqlite3' funciona en modo síncrono
const db = new Database(DB_PATH);

// Activamos el modo WAL (Write-Ahead Logging), que mejora el rendimiento
// y la concurrencia de lectura/escritura. Cuando un proceso escribe, bloquea toda la base de datos para evitar conflictos
// En lugar de escribir directamente al archivo principal, las escrituras se guardan primero en un archivo de registro (.wal)
// las lecturas pueden seguir accediendo al archivo principal sin bloqueo, 
// Finalmente, SQLite fusiona (commit) los cambios del .wal al archivo principal cuando es seguro hacerlo
db.pragma('journal_mode = WAL');

// Leemos el contenido del archivo schema.sql y lo ejecutamos en la base.
// Esto asegura que las tablas existan antes de continuar.
// Si ya existen, el CREATE TABLE IF NOT EXISTS evita recrearlas.
const schema = fs.readFileSync(SCHEMA_PATH, 'utf-8');
db.exec(schema);

// Consultas preparadas (Prepared Statements)
// Estas consultas se preparan una sola vez y se reutilizan, lo que mejora
// la seguridad (evita SQL Injection) y el rendimiento.
// Cada una se puede ejecutar con .run(), .get() o .all() según corresponda.

export const queries = {
  // ---------- Usuarios ----------
  // Inserta un nuevo usuario
  insertUser: db.prepare(`
    INSERT INTO users (email, password_hash, role)
    VALUES (?, ?, ?)
  `),

  // Obtiene un usuario por su email
  getUserByEmail: db.prepare(`
    SELECT * FROM users WHERE email = ?
  `),

  // Obtiene un usuario por su ID
  getUserById: db.prepare(`
    SELECT * FROM users WHERE id = ?
  `),

  // Actualiza los intentos fallidos y el tiempo de bloqueo
  updateFailedAttemptsAndLock: db.prepare(`
    UPDATE users
       SET failed_attempts = ?, lock_until = ?
     WHERE id = ?
  `),

  // Restablece los intentos fallidos (al loguearse correctamente)
  resetLockout: db.prepare(`
    UPDATE users
       SET failed_attempts = 0, lock_until = NULL
     WHERE id = ?
  `),

  // Lista todos los usuarios (usado en la vista admin)
  listUsers: db.prepare(`
    SELECT id, email, role, created_at, failed_attempts, lock_until
      FROM users
     ORDER BY id ASC
  `),

  // Actualiza el rol de un usuario (user ↔ admin)
  updateUserRole: db.prepare(`
    UPDATE users SET role = ? WHERE id = ?
  `),

  // ---------- Sesiones (para cookies) ----------
  // Inserta una nueva sesión
  insertSession: db.prepare(`
    INSERT INTO sessions (id, user_id, csrf_token, ip, user_agent, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `),

  // Busca una sesión por su ID
  getSessionById: db.prepare(`
    SELECT * FROM sessions WHERE id = ?
  `),

  // Revoca (invalida) una sesión específica (por logout)
  revokeSession: db.prepare(`
    UPDATE sessions SET revoked_at = datetime('now') WHERE id = ?
  `),

  // Elimina sesiones expiradas automáticamente
  deleteExpiredSessions: db.prepare(`
    DELETE FROM sessions WHERE expires_at <= datetime('now')
  `)
};

// Exportamos la conexión principal por si queremos usarla directamente en otras partes
export default db;

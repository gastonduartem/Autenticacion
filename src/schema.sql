-- Archivo: schema.sql
-- Propósito: Definir las tablas principales para PassPort Inc.


-- Tabla: users
-- Guarda la información de cada usuario registrado

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,      -- Identificador único autoincremental
  email TEXT NOT NULL UNIQUE,                -- Correo electrónico (debe ser único)
  password_hash TEXT NOT NULL,               -- Contraseña cifrada con bcrypt (NO texto plano)
  role TEXT NOT NULL DEFAULT 'user',         -- Rol del usuario: 'user' o 'admin'
  failed_attempts INTEGER NOT NULL DEFAULT 0,-- Contador de intentos fallidos de login
  lock_until DATETIME DEFAULT NULL,          -- Fecha/hora hasta la que la cuenta está bloqueada
  created_at DATETIME NOT NULL DEFAULT (datetime('now')) -- Fecha de registro
);

-- Tabla: sessions
-- Guarda las sesiones activas (flujo con cookies persistentes)

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,                       -- ID único de sesión (token aleatorio base64url)
  user_id INTEGER NOT NULL,                  -- Usuario al que pertenece la sesión
  csrf_token TEXT NOT NULL,                  -- Token aleatorio para validar formularios (CSRF)
  ip TEXT,                                   -- IP del usuario (opcional, útil para auditoría)
  user_agent TEXT,                           -- Navegador / cliente (opcional)
  created_at DATETIME NOT NULL DEFAULT (datetime('now')), -- Cuándo se creó
  expires_at DATETIME NOT NULL,              -- Cuándo expira (por ej. 7 días desde login)
  revoked_at DATETIME DEFAULT NULL,          -- Si se revoca manualmente al hacer logout
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Índices auxiliares
-- Mejoran rendimiento de consultas frecuentes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email); -- buscar usuarios por correo
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id); -- listar las sesiones de un usuario rápido
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at); -- limpiar sesiones expiradas eficientemente

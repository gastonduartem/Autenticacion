// =====================================================
// Archivo: src/routes/auth-jwt.js
// Propósito: Registro y login que devuelven JWT.
// Cambio: el registro respeta el rol recibido ('user'|'admin')
//         y si no viene o es inválido, usa 'user' por defecto.
// =====================================================

import { Router } from 'express';        // Router de Express para agrupar rutas
import { queries } from '../db.js';      // Consultas preparadas a SQLite
import bcrypt from 'bcryptjs';           // Hash y verificación de contraseñas
import jwt from 'jsonwebtoken';          // Firmado y verificación de JWT

const router = Router();                 // Instancia del router

// Clave secreta para firmar el token JWT (en prod usar variable de entorno)
const JWT_SECRET = process.env.JWT_SECRET || 'dev-insecure-secret-change-me';

// Tiempo de vida del access token (15 minutos en segundos)
const ACCESS_TOKEN_TTL_SECONDS = 60 * 15;

// Helper: firma un JWT con payload mínimo (id y role) y TTL configurado
function signAccessToken(user) {
  // Payload mínimo: subject (id) y role (user/admin)
  const payload = { sub: user.id, role: user.role };

  // Firmamos con HS256 y caducidad de 15 minutos
  return jwt.sign(payload, JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: ACCESS_TOKEN_TTL_SECONDS
  });
}

// -----------------------------------------------------
// POST /register-jwt
// Crea un usuario con el rol indicado (user/admin) y
// devuelve un access_token para autenticarse por JWT.
// -----------------------------------------------------
router.post('/register-jwt', async (req, res) => {
  try {
    // Leemos email, password y rol desde el body
    const { email, password, role } = req.body || {};

    // Validamos presencia de email y password (ambos deben ser string)
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Email y password son requeridos' });
    }

    // Normalizamos el rol: si es 'admin' o 'user', lo usamos; si no, default 'user'
    const finalRole = (role === 'admin' || role === 'user') ? role : 'user';

    // Hasheamos la contraseña con bcrypt (12 rondas)
    const password_hash = await bcrypt.hash(password, 12);

    // Insertamos el nuevo usuario en la tabla users
    queries.insertUser.run(email.trim().toLowerCase(), password_hash, finalRole);

    // Leemos al usuario recién creado (para firmar el token)
    const user = queries.getUserByEmail.get(email.trim().toLowerCase());

    // Firmamos el access token (JWT)
    const access_token = signAccessToken(user);

    // Respondemos con token y metadatos
    return res.status(201).json({
      message: `Usuario creado con rol ${user.role}. Usa el token para autenticarte.`,
      access_token,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      how_to_use: 'Authorization: Bearer <access_token>'
    });

  } catch (err) {
    // Si el email ya existe, SQLite manda UNIQUE constraint
    if (String(err).includes('UNIQUE constraint failed: users.email')) {
      return res.status(409).json({ error: 'Ese email ya está registrado' });
    }
    console.error('Error en register-jwt:', err);
    return res.status(500).json({ error: 'Error al registrar usuario (JWT)' });
  }
});

// -----------------------------------------------------
// POST /login-jwt
// Verifica credenciales; si son válidas, devuelve un
// access_token (JWT) con el role del usuario.
// -----------------------------------------------------
router.post('/login-jwt', async (req, res) => {
  try {
    // Leemos email y password del body
    const { email, password } = req.body || {};

    // Validamos presencia de ambos campos
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Email y password son requeridos' });
    }

    // Buscamos usuario por email
    const user = queries.getUserByEmail.get(email.trim().toLowerCase());
    if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });

    // Revisamos si está bloqueado por fuerza bruta (lock_until en el futuro)
    if (user.lock_until && new Date(user.lock_until) > new Date()) {
      return res.status(403).json({ error: 'Cuenta bloqueada temporalmente. Intenta más tarde.' });
    }

    // Comparamos password plano vs hash guardado
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      // Sumamos intentos fallidos y bloqueamos a la 5ta falla por 15 min
      const attempts = user.failed_attempts + 1;
      let lockUntil = null;
      if (attempts >= 5) {
        const lockDate = new Date(Date.now() + 15 * 60 * 1000);
        lockUntil = lockDate.toISOString().slice(0, 19).replace('T', ' ');
      }
      queries.updateFailedAttemptsAndLock.run(attempts, lockUntil, user.id);
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // Si login correcto, reseteamos el lockout/contador
    queries.resetLockout.run(user.id);

    // Firmamos un token de acceso con su rol actual (user/admin)
    const access_token = signAccessToken(user);

    // Respondemos con el token y cómo usarlo
    return res.json({
      message: 'Login exitoso (JWT).',
      access_token,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      how_to_use: 'Authorization: Bearer <access_token>'
    });

  } catch (err) {
    console.error('Error en login-jwt:', err);
    return res.status(500).json({ error: 'Error al iniciar sesión (JWT)' });
  }
});

export default router; // Export del router para usar en server.js

// =====================================================
// Archivo: src/routes/auth-cookie.js
// Propósito: Registro/login/logout con sesiones en DB.
// Cambio: el registro respeta el rol recibido ('user'|'admin')
//         y si no viene o es inválido, usa 'user' por defecto.
//         Cookies con secure:false en local (HTTP).
// =====================================================

import { Router } from 'express';        // Router de Express
import { queries } from '../db.js';      // Consultas a SQLite (users/sessions)
import bcrypt from 'bcryptjs';           // Hash de contraseñas
import crypto from 'node:crypto';        // IDs aleatorios (sid, csrfToken)

const router = Router();                 // Instancia del router

// TTL de la sesión persistente (en días)
const SESSION_TTL_DAYS = 7;

// Helper: genera fecha "YYYY-MM-DD HH:MM:SS" a N días desde ahora (para SQLite)
function expiresFromNow(days) {
  const now = new Date();
  now.setDate(now.getDate() + days);
  return now.toISOString().slice(0, 19).replace('T', ' ');
}

// -----------------------------------------------------
// POST /register-cookie
// Crea usuario con rol indicado y responde mensaje.
// -----------------------------------------------------
router.post('/register-cookie', async (req, res) => {
  try {
    // Leemos email, password y rol del body JSON
    const { email, password, role } = req.body || {};

    // Validamos email/password
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Email y password son requeridos' });
    }

    // Normalizamos el rol (default: 'user')
    const finalRole = (role === 'admin' || role === 'user') ? role : 'user';

    // Hasheamos la contraseña
    const password_hash = await bcrypt.hash(password, 12);

    // Insertamos usuario con el rol final
    queries.insertUser.run(email.trim().toLowerCase(), password_hash, finalRole);

    // Respondemos OK
    return res.status(201).json({ message: `Usuario registrado con rol ${finalRole}. Ahora puedes iniciar sesión.` });

  } catch (err) {
    // Error típico: email duplicado
    if (String(err).includes('UNIQUE constraint failed: users.email')) {
      return res.status(409).json({ error: 'Ese email ya está registrado' });
    }
    console.error('Error en registro:', err);
    return res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// -----------------------------------------------------
// POST /login-cookie
// Verifica credenciales, crea sesión (DB) y setea cookies.
// -----------------------------------------------------
router.post('/login-cookie', async (req, res) => {
  try {
    // Leemos email y password del body
    const { email, password } = req.body || {};

    // Validamos entradas
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Email y password son requeridos' });
    }

    // Buscamos usuario
    const user = queries.getUserByEmail.get(email.trim().toLowerCase());
    if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });

    // Verificamos lockout temporal por fuerza bruta
    if (user.lock_until && new Date(user.lock_until) > new Date()) {
      return res.status(403).json({ error: 'Cuenta bloqueada temporalmente. Intenta más tarde.' });
    }

    // Comparamos password plano vs hash
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      // Aumentamos contador y bloqueamos a la 5ta falla por 15 min
      const attempts = user.failed_attempts + 1;
      let lockUntil = null;
      if (attempts >= 5) {
        const lockDate = new Date(Date.now() + 15 * 60 * 1000);
        lockUntil = lockDate.toISOString().slice(0, 19).replace('T', ' ');
      }
      queries.updateFailedAttemptsAndLock.run(attempts, lockUntil, user.id);
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // Reset del lockout al loguear correctamente
    queries.resetLockout.run(user.id);

    // Generamos ID de sesión (sid) y token CSRF (para double-submit)
    const sid = crypto.randomBytes(32).toString('base64url');
    const csrfToken = crypto.randomBytes(24).toString('base64url');

    // Calculamos expiración y guardamos la sesión en DB
    const expires_at = expiresFromNow(SESSION_TTL_DAYS);
    queries.insertSession.run(sid, user.id, csrfToken, req.ip, req.get('user-agent') || '', expires_at);

    // Seteamos cookie de sesión (HttpOnly) — en local, secure:false porque es HTTP
    res.cookie('sid', sid, {
      httpOnly: true,     // Inaccesible por JS (mitiga XSS)
      secure: false,      // Local HTTP: false | Producción HTTPS: true
      sameSite: 'lax',    // Mitiga CSRF básico
      path: '/',
      maxAge: 1000 * 60 * 60 * 24 * SESSION_TTL_DAYS
    });

    // Seteamos cookie del token CSRF (NO HttpOnly) para double-submit
    res.cookie('csrfToken', csrfToken, {
      httpOnly: false,    // Debe ser accesible por JS (leer y enviar en X-CSRF-Token)
      secure: false,      // Local HTTP: false | Producción HTTPS: true
      sameSite: 'lax',
      path: '/',
      maxAge: 1000 * 60 * 60 * 24 * SESSION_TTL_DAYS
    });

    // Respondemos con datos mínimos
    return res.json({
      message: 'Inicio de sesión exitoso',
      user: { id: user.id, email: user.email, role: user.role }
    });

  } catch (err) {
    console.error('Error en login:', err);
    return res.status(500).json({ error: 'Error al iniciar sesión' });
  }
});

// -----------------------------------------------------
// POST /logout-cookie
// Revoca la sesión (DB) y limpia cookies en el cliente.
// -----------------------------------------------------
router.post('/logout-cookie', (req, res) => {
  try {
    // Leemos cookie 'sid' que identifica la sesión
    const sid = req.cookies.sid;
    if (!sid) return res.status(400).json({ error: 'No hay sesión activa' });

    // Marcamos la sesión como revocada en DB
    queries.revokeSession.run(sid);

    // Limpiamos cookies en el navegador
    res.clearCookie('sid');
    res.clearCookie('csrfToken');

    // Respondemos OK
    return res.json({ message: 'Sesión cerrada correctamente' });

  } catch (err) {
    console.error('Error en logout:', err);
    return res.status(500).json({ error: 'Error al cerrar sesión' });
  }
});

export default router; // Export del router para usar en server.js

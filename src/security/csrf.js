// Archivo: src/security/csrf.js
// Propósito: Middleware para proteger rutas con sesiones
//            (cookies) contra ataques CSRF.

// Importamos las consultas preparadas a la base de datos.
import { queries } from '../db.js';


// Middleware requireCSRF

// Se usa junto con authCookie. Verifica que el usuario envíe:
//  1) Cookie 'csrfToken' (no HttpOnly) enviada por el servidor al hacer login.
//  2) Header 'X-CSRF-Token' con el mismo valor.
//  3) Coincidencia del valor con el guardado en la sesión en la base de datos.
//
// Si cualquiera de estos pasos falla, se bloquea la petición (403).
export function requireCSRF(req, res, next) {
  try {
    // Leer el ID de sesión desde la cookie (para buscar en DB)
    const sid = req.cookies?.sid;
    if (!sid) {
      return res.status(401).json({ error: 'No autenticado (falta cookie sid)' });
    }

    // Leer el token CSRF desde la cookie y el header
    const csrfCookie = req.cookies?.csrfToken;
    const csrfHeader = req.get('X-CSRF-Token'); // sensible a mayúsculas exactas

    // Validamos presencia
    if (!csrfCookie || !csrfHeader) {
      return res.status(403).json({ error: 'CSRF token faltante' });
    }

    // Buscamos la sesión en DB
    const session = queries.getSessionById.get(sid);
    if (!session) {
      return res.status(401).json({ error: 'Sesión no encontrada' });
    }

    // Comprobamos coincidencias (triple verificación)
    const match = csrfCookie === csrfHeader && csrfHeader === session.csrf_token;

    if (!match) {
      return res.status(403).json({ error: 'CSRF token inválido o no coincide' });
    }

    // Todo correcto → pasa al siguiente middleware o controlador
    return next();

  } catch (err) {
    console.error('CSRF middleware error:', err);
    return res.status(500).json({ error: 'Error verificando CSRF token' });
  }
}

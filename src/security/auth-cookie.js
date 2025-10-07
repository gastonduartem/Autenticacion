// Archivo: src/security/auth-cookie.js
// Propósito: Middleware para autenticar usuarios usando
//            sesiones persistentes guardadas en SQLite
//            y enviadas por cookie HttpOnly 'sid'.


// Importamos las consultas preparadas a la base de datos.
import { queries } from '../db.js';

// Middleware principal: verifica la cookie 'sid', carga la sesión y el usuario.
// - Si es válido: coloca `req.user` y `req.session` y llama next().
// - Si no: responde 401 (no autenticado).
export function authCookie(req, res, next) {
  try {
    // Leemos la cookie 'sid' que envía el navegador automáticamente.
    const sid = req.cookies?.sid;

    // 2) Si no hay cookie, no hay sesión -> no autenticado.
    if (!sid) {
      return res.status(401).json({ error: 'No autenticado (falta cookie sid)' });
    }

    // Buscamos la sesión en DB por su id.
    const session = queries.getSessionById.get(sid);

    // Validamos que la sesión exista y no esté revocada ni expirada.
    if (!session) {
      return res.status(401).json({ error: 'Sesión inválida' });
    }
    if (session.revoked_at) {
      return res.status(401).json({ error: 'Sesión revocada' });
    }
    // Comparar expiración con el momento actual (en SQLite guardamos texto "YYYY-MM-DD HH:MM:SS")
    if (new Date(session.expires_at) <= new Date()) {
      return res.status(401).json({ error: 'Sesión expirada' });
    }

    // Cargamos el usuario dueño de la sesión.
    const user = queries.getUserById.get(session.user_id);
    if (!user) {
      return res.status(401).json({ error: 'Usuario inexistente' });
    }

    // Adjuntamos la información útil al objeto req para siguientes middlewares/rutas.
    //    - req.user: datos del usuario (id, email, role, etc.)
    //    - req.session: info de la sesión (id, csrf_token, etc.)
    req.user = {
      id: user.id,
      email: user.email,
      role: user.role
    };
    req.session = {
      id: session.id,
      csrf_token: session.csrf_token,
      user_id: session.user_id,
      expires_at: session.expires_at
    };

    // Llamamos al siguiente middleware/handler.
    return next();

  } catch (err) {
    // Si algo inesperado sucede, devolvemos 500 para no filtrar detalles.
    console.error('authCookie error:', err);
    return res.status(500).json({ error: 'Error de autenticación (cookie)' });
  }
}

// Middleware auxiliar: exige un rol específico (por ejemplo, 'admin').
// Uso: router.get('/admin/route', authCookie, requireRole('admin'), handler)
export function requireRole(role) {
  return (req, res, next) => {
    try {
      // Si no hay usuario en req, no pasó por authCookie o falló.
      if (!req.user) {
        return res.status(401).json({ error: 'No autenticado' });
      }

      // Comprobamos si el rol coincide con el requerido.
      if (req.user.role !== role) {
        return res.status(403).json({ error: 'No autorizado (rol insuficiente)' });
      }

      // Todo ok -> siguiente middleware/handler.
      return next();
    } catch (err) {
      console.error('requireRole error:', err);
      return res.status(500).json({ error: 'Error verificando rol' });
    }
  };
}

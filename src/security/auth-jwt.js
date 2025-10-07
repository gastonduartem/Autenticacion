// Archivo: src/security/auth-jwt.js
// Propósito: Middleware para autenticar y autorizar
//            usuarios que usan JSON Web Tokens (JWT).

// Importamos jsonwebtoken para verificar la validez y firma del token.
import jwt from 'jsonwebtoken';

// Clave secreta para verificar los tokens.
// Debe coincidir con la usada en auth-jwt.js para firmarlos.
const JWT_SECRET = process.env.JWT_SECRET || 'dev-insecure-secret-change-me';

// Middleware principal: verifica el token JWT en el header Authorization.
// Si es válido, coloca la info del usuario (id, role) en req.user.
// Si no, devuelve 401 (no autenticado).
export function authJWT(req, res, next) {
  try {
    // Obtenemos el header Authorization.
    const authHeader = req.get('Authorization');

    // Validamos formato: debe venir como "Bearer <token>".
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Falta header Authorization: Bearer <token>' });
    }

    // Extraemos el token (todo lo que viene después de "Bearer ").
    const token = authHeader.substring(7);

    // Verificamos el token con jsonwebtoken.verify.
    // Si el token fue firmado con la misma clave y no expiró, devuelve el payload decodificado.
    const payload = jwt.verify(token, JWT_SECRET);

    // Adjuntamos los datos del usuario al objeto req (útil para las rutas).
    req.user = {
      id: payload.sub,  // el "subject" es el ID del usuario
      role: payload.role
    };

    // Continuamos con la siguiente función o controlador.
    return next();

  } catch (err) {
    // Si falla la verificación, puede ser por expiración o token inválido.
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expirado' });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Token inválido o alterado' });
    }

    console.error('authJWT error:', err);
    return res.status(500).json({ error: 'Error al verificar token' });
  }
}

// Middleware auxiliar para roles (igual que el de cookies).
// Uso: router.get('/admin', authJWT, requireRole('admin'), handler)
export function requireRole(role) {
  return (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'No autenticado (falta usuario en req)' });
      }

      if (req.user.role !== role) {
        return res.status(403).json({ error: 'No autorizado (rol insuficiente)' });
      }

      return next();
    } catch (err) {
      console.error('requireRole error:', err);
      return res.status(500).json({ error: 'Error verificando rol' });
    }
  };
}

// Archivo: src/routes/me.js
// Propósito: Endpoints "perfil" que devuelven la info
//            del usuario autenticado, tanto por cookies
//            como por JWT.

// Importamos Router de Express.
import { Router } from 'express';

// Importamos middlewares de seguridad.
import { authCookie } from '../security/auth-cookie.js';
import { authJWT } from '../security/auth-jwt.js';

// Creamos el router (mini app).
const router = Router();

// GET /me-cookie
// Devuelve info del usuario autenticado vía sesión-cookie
router.get('/me-cookie', authCookie, (req, res) => {
  // Si authCookie valida correctamente, req.user ya contiene los datos.
  res.json({
    message: 'Usuario autenticado mediante cookie',
    user: req.user,
    session: req.session
  });
});

// GET /me-jwt
// Devuelve info del usuario autenticado vía JWT
router.get('/me-jwt', authJWT, (req, res) => {
  // Si authJWT valida el token, req.user ya contiene el id y rol del usuario.
  res.json({
    message: 'Usuario autenticado mediante JWT',
    user: req.user
  });
});

// Exportamos el router para usarlo en server.js
export default router;

// Archivo: src/routes/admin.js
// Propósito: Rutas exclusivas para administradores.

// Importamos Router para definir endpoints.
import { Router } from 'express';

// Importamos las consultas de la DB.
import { queries } from '../db.js';

// Importamos middlewares de seguridad:
// - authCookie → valida sesión con cookies.
// - authJWT → valida token JWT.
// - requireRole → asegura que el usuario tenga el rol requerido.
// - requireCSRF → protege las peticiones con cookies contra CSRF.
import { authCookie, requireRole as requireRoleCookie } from '../security/auth-cookie.js';
import { authJWT, requireRole as requireRoleJWT } from '../security/auth-jwt.js';
import { requireCSRF } from '../security/csrf.js';

// Creamos el router.
const router = Router();


// GET /admin/users-cookie
// Lista de usuarios (solo para admins autenticados con cookies)
router.get('/admin/users-cookie', authCookie, requireRoleCookie('admin'), (req, res) => {
  try {
    const users = queries.listUsers.all();
    return res.json({
      message: 'Listado de usuarios (cookie)',
      total: users.length,
      users
    });
  } catch (err) {
    console.error('Error listando usuarios (cookie):', err);
    return res.status(500).json({ error: 'Error al listar usuarios' });
  }
});


// PATCH /admin/users/:id/role-cookie
// Cambia el rol de un usuario (solo admin con cookie)
// Requiere token CSRF válido.
router.patch(
  '/admin/users/:id/role-cookie',
  authCookie,              // verifica sesión
  requireRoleCookie('admin'), // requiere rol admin
  requireCSRF,             // verifica token CSRF
  (req, res) => {
    try {
      const targetId = parseInt(req.params.id);
      const { role } = req.body;

      if (!['user', 'admin'].includes(role)) {
        return res.status(400).json({ error: 'Rol inválido (solo user o admin)' });
      }

      // No permitir que el admin se cambie a sí mismo
      if (req.user.id === targetId) {
        return res.status(400).json({ error: 'No puedes cambiar tu propio rol' });
      }

      queries.updateUserRole.run(role, targetId);
      return res.json({ message: `Rol del usuario ${targetId} actualizado a ${role}` });
    } catch (err) {
      console.error('Error cambiando rol (cookie):', err);
      return res.status(500).json({ error: 'Error al cambiar rol' });
    }
  }
);


// GET /admin/users-jwt
// Lista de usuarios (solo para admins autenticados con JWT)
router.get('/admin/users-jwt', authJWT, requireRoleJWT('admin'), (req, res) => {
  try {
    const users = queries.listUsers.all();
    return res.json({
      message: 'Listado de usuarios (JWT)',
      total: users.length,
      users
    });
  } catch (err) {
    console.error('Error listando usuarios (JWT):', err);
    return res.status(500).json({ error: 'Error al listar usuarios' });
  }
});


// PATCH /admin/users/:id/role-jwt
// Cambia el rol de un usuario (solo admin con JWT)
router.patch(
  '/admin/users/:id/role-jwt',
  authJWT,
  requireRoleJWT('admin'),
  (req, res) => {
    try {
      const targetId = parseInt(req.params.id);
      const { role } = req.body;

      if (!['user', 'admin'].includes(role)) {
        return res.status(400).json({ error: 'Rol inválido (solo user o admin)' });
      }

      if (req.user.id === targetId) {
        return res.status(400).json({ error: 'No puedes cambiar tu propio rol' });
      }

      queries.updateUserRole.run(role, targetId);
      return res.json({ message: `Rol del usuario ${targetId} actualizado a ${role}` });
    } catch (err) {
      console.error('Error cambiando rol (JWT):', err);
      return res.status(500).json({ error: 'Error al cambiar rol' });
    }
  }
);

// Exportamos el router.
export default router;

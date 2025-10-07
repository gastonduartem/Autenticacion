// =====================================================
// Archivo: src/server.js
// Propósito: Configurar Express, seguridad y rutas.
// Cambio: desactivamos CSP de Helmet SOLO en dev
//         para permitir JS externo sin nonce.
// =====================================================

import express from 'express';              // Framework HTTP
import helmet from 'helmet';                // Cabeceras de seguridad
import cookieParser from 'cookie-parser';   // Lectura de cookies
import cors from 'cors';                    // Permitir CORS para front local
import path from 'node:path';               // Manejo de rutas de archivos
import { fileURLToPath } from 'node:url';   // Soporte __dirname en ES Modules

// Rutas (sin cambios de import)
import cookieAuthRoutes from './routes/auth-cookie.js';
import jwtAuthRoutes from './routes/auth-jwt.js';
import adminRoutes from './routes/admin.js';
import meRoutes from './routes/me.js';

const __filename = fileURLToPath(import.meta.url); // Ruta del archivo actual
const __dirname = path.dirname(__filename);        // Carpeta del archivo actual

const app = express();                              // Instancia de Express

// --- Seguridad base ---
// Desactivamos CSP para desarrollo, así los <script src> externos funcionan sin complicaciones.
// En producción, conviene activar CSP con una política explícita.
app.use(helmet({ contentSecurityPolicy: false }));

// --- CORS ---
// Permitimos que el navegador envíe cookies (credentials: true) desde front local.
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:8080'],
  credentials: true
}));

// --- Body parsers ---
// Soporte JSON
app.use(express.json());
// Soporte formularios <form> urlencoded
app.use(express.urlencoded({ extended: true }));

// --- Cookies ---
app.use(cookieParser());

// --- Archivos estáticos ---
// Servimos /src/views como raíz estática (HTML, JS, CSS).
app.use(express.static(path.join(__dirname, 'views')));

// --- Rutas de la app ---
app.use(cookieAuthRoutes);
app.use(jwtAuthRoutes);
app.use(adminRoutes);
app.use(meRoutes);

// Healthcheck
app.get('/health', (_req, res) => res.json({ ok: true }));

// --- Arranque del servidor ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`[PassPort Inc] Auth MVP escuchando en http://localhost:${PORT}`);
});

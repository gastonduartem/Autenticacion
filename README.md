# 🪪 PassPort Inc. — Sistema de Autenticación y Sesiones Seguras (MVP)

Este proyecto implementa el sistema de **autenticación y gestión de sesiones** para la startup ficticia **PassPort Inc.**, cumpliendo con los requerimientos obligatorios del ejercicio:  
registro, login, roles, seguridad con cookies o JWT, CSRF, hashing, control de fuerza bruta y más.

---

## 🚀 Tecnologías utilizadas

- **Node.js** (runtime)
- **Express** (servidor HTTP)
- **better-sqlite3** (base de datos embebida)
- **bcryptjs** (hashing seguro de contraseñas)
- **jsonwebtoken (JWT)** (autenticación sin estado)
- **helmet** (cabeceras de seguridad HTTP)
- **cookie-parser** (manejo de cookies)
- **cors** (Cross-Origin Resource Sharing)

---

## 🧩 Funcionalidades principales

| Funcionalidad                     | Descripción                                         |
| --------------------------------- | --------------------------------------------------- |
| 🧑‍💻 **Registro/Login con cookies** | Crea sesión persistente almacenada en DB.           |
| 🔐 **Registro/Login con JWT**     | Genera y valida tokens firmados HS256.              |
| 🍪 **Gestión de sesiones**        | Las cookies guardan `sid` y `csrfToken`.            |
| 🔒 **Hashing de contraseñas**     | Contraseñas cifradas con bcryptjs (12 salt rounds). |
| 🧱 **CSRF Protection**            | Double Submit Cookie Pattern.                       |
| 🧍‍♂️ **RBAC (Roles)**               | `user` y `admin` con rutas protegidas.              |
| 🚫 **Fuerza bruta**               | 5 intentos → bloqueo temporal (15 min).             |
| 🧠 **Cabeceras seguras**          | Helmet y cookies con flags seguras.                 |

---

## 📁 Estructura del proyecto

passport-inc/
├─ src/
│ ├─ db.js
│ ├─ schema.sql
│ ├─ server.js
│ ├─ security/
│ │ ├─ auth-cookie.js
│ │ ├─ auth-jwt.js
│ │ ├─ csrf.js
│ │ └─ rate-limit.js (opcional futuro)
│ ├─ routes/
│ │ ├─ auth-cookie.js
│ │ ├─ auth-jwt.js
│ │ ├─ admin.js
│ │ └─ me.js
│ └─ views/
│ ├─ register-cookie.html
│ ├─ login-cookie.html
│ ├─ register-jwt.html
│ ├─ login-jwt.html
│
├─ package.json
└─ README.md

---

## ⚙️ Instalación

### 1️⃣ Clonar el proyecto

```bash
git clone https://github.com/tuusuario/passport-inc.git
cd passport-inc

```

### 2️⃣ Instalar dependencias

npm install

### 3️⃣ Ejecutar el servidor

npm run start

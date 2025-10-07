// =====================================================
// Archivo: src/views/admin.js
// Propósito: Hacer llamadas a endpoints admin tanto
//            con Cookies (incluye CSRF) como con JWT.
//            Renderizar lista de usuarios y cambiar roles.
// =====================================================

// --- Helpers de DOM ---
// Obtenemos referencias a elementos del HTML por su id
const modeCookie = document.getElementById('mode-cookie'); // Radio "Cookies"
const modeJwt    = document.getElementById('mode-jwt');    // Radio "JWT"
const jwtConfig  = document.getElementById('jwt-config');  // Panel token JWT
const cookieConfig = document.getElementById('cookie-config'); // Panel cookies
const jwtInput   = document.getElementById('jwt');         // Textarea para token
const btnList    = document.getElementById('btn-list');    // Botón listar usuarios
const btnChange  = document.getElementById('btn-change');  // Botón cambiar rol
const userId     = document.getElementById('userId');      // Input ID usuario
const newRole    = document.getElementById('newRole');     // Selector nuevo rol
const table      = document.getElementById('tbl');         // Tabla de usuarios
const tbody      = document.getElementById('tbody');       // Body de la tabla
const out        = document.getElementById('out');         // Salida textual

// --- Utilidad: obtener valor de una cookie por nombre ---
// Parsea document.cookie (formato "k=v; k2=v2; ...") y devuelve el valor de la clave pedida.
function getCookie(name) {
  // Creamos un patrón "name=" y buscamos dentro de document.cookie
  const match = document.cookie.split('; ').find(p => p.startsWith(name + '='));
  // Si existe, devolvemos el valor decodificado; si no, null
  return match ? decodeURIComponent(match.split('=').slice(1).join('=')) : null;
}

// --- Manejo del selector de modo ---
// Cuando el usuario marca JWT, mostramos el panel de token; si marca cookies, lo ocultamos.
function refreshModeUI() {
  // Si está seleccionado el modo JWT...
  if (modeJwt.checked) {
    jwtConfig.style.display = '';       // Mostramos el bloque de configuración JWT
    cookieConfig.style.display = 'none';// Ocultamos el bloque de cookies
  } else {
    // Si está el modo cookies...
    jwtConfig.style.display = 'none';   // Ocultamos configuración JWT
    cookieConfig.style.display = '';    // Mostramos recordatorio de cookies
  }
}
// Asociamos el refresco de UI a cambios en los radios
modeCookie.addEventListener('change', refreshModeUI);
modeJwt.addEventListener('change', refreshModeUI);
// Y lo llamamos una vez al cargar
refreshModeUI();

// --- Render de usuarios en tabla ---
// Recibe un array de usuarios [{id,email,role,...}] y lo imprime en la tabla
function renderUsers(users) {
  // Si no hay usuarios, ocultamos la tabla y mostramos mensaje
  if (!Array.isArray(users) || users.length === 0) {
    table.style.display = 'none';
    out.textContent = 'No hay usuarios para mostrar.';
    return;
  }

  // Si hay usuarios, vaciamos el tbody y lo rellenamos
  tbody.innerHTML = '';
  for (const u of users) {
    // Creamos una fila
    const tr = document.createElement('tr');
    // Agregamos celdas con datos del usuario
    tr.innerHTML = `
      <td>${u.id}</td>
      <td>${u.email}</td>
      <td>${u.role}</td>
      <td>${u.created_at ?? ''}</td>
      <td>${u.failed_attempts ?? 0}</td>
      <td>${u.lock_until ?? ''}</td>
    `;
    // Adjuntamos la fila al cuerpo de la tabla
    tbody.appendChild(tr);
  }
  // Mostramos la tabla
  table.style.display = '';
}

// --- Llamadas con JWT ---
// Pide la lista de usuarios usando Authorization: Bearer <token>
async function listUsersJWT() {
  // Leemos token desde el textarea
  const token = jwtInput.value.trim();
  // Si no hay token, avisamos y abortamos
  if (!token) return out.textContent = 'Pegá un token JWT para listar (modo JWT).';

  // Hacemos la petición GET con el header Authorization
  const res = await fetch('/admin/users-jwt', {
    headers: { Authorization: `Bearer ${token}` }
  });

  // Obtenemos el texto de respuesta
  const text = await res.text();
  try {
    // Intentamos parsearlo como JSON
    const data = JSON.parse(text);
    out.textContent = `GET /admin/users-jwt — ${res.status}\n\n` + JSON.stringify(data, null, 2);
    // Si existe data.users, lo renderizamos en tabla
    if (Array.isArray(data.users)) renderUsers(data.users);
  } catch {
    // Si no era JSON, mostramos texto plano
    out.textContent = `GET /admin/users-jwt — ${res.status}\n\n` + text;
  }
}

// Cambia el rol de un usuario con Authorization: Bearer <token>
async function changeRoleJWT(id, role) {
  // Leemos el token
  const token = jwtInput.value.trim();
  // Validaciones básicas
  if (!token) return out.textContent = 'Pegá un token JWT para cambiar rol (modo JWT).';
  if (!id)     return out.textContent = 'Ingresá un ID de usuario válido.';
  if (!['user','admin'].includes(role)) return out.textContent = 'Rol inválido.';

  // Ejecutamos PATCH con header Authorization y body JSON
  const res = await fetch(`/admin/users/${id}/role-jwt`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`
    },
    body: JSON.stringify({ role })
  });

  // Mostramos la respuesta
  const text = await res.text();
  out.textContent = `PATCH /admin/users/${id}/role-jwt — ${res.status}\n\n` + text;
}

// --- Llamadas con Cookies (CSRF) ---
// Pide la lista de usuarios usando cookies (requiere login-cookie previo)
async function listUsersCookie() {
  // Añadimos credentials:'include' para que el navegador envíe cookies
  const res = await fetch('/admin/users-cookie', { credentials: 'include' });
  const text = await res.text();
  try {
    // Parseamos JSON si es posible
    const data = JSON.parse(text);
    out.textContent = `GET /admin/users-cookie — ${res.status}\n\n` + JSON.stringify(data, null, 2);
    if (Array.isArray(data.users)) renderUsers(data.users);
  } catch {
    // Si no era JSON, mostramos texto plano
    out.textContent = `GET /admin/users-cookie — ${res.status}\n\n` + text;
  }
}

// Cambia el rol con cookies + CSRF (double submit)
async function changeRoleCookie(id, role) {
  // Validaciones
  if (!id) return out.textContent = 'Ingresá un ID de usuario válido.';
  if (!['user','admin'].includes(role)) return out.textContent = 'Rol inválido.';

  // Recuperamos el csrfToken desde las cookies
  const csrf = getCookie('csrfToken');
  // Si falta el token, probablemente no estás logueado con cookies
  if (!csrf) return out.textContent = 'Falta csrfToken. Iniciá sesión en /login-cookie.html.';

  // Ejecutamos PATCH con:
  // - credentials:'include' para enviar cookies
  // - header X-CSRF-Token con el valor de la cookie
  const res = await fetch(`/admin/users/${id}/role-cookie`, {
    method: 'PATCH',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrf
    },
    body: JSON.stringify({ role })
  });

  // Mostramos la respuesta
  const text = await res.text();
  out.textContent = `PATCH /admin/users/${id}/role-cookie — ${res.status}\n\n` + text;
}

// --- Listeners de botones ---
// Cuando se hace click en "Listar usuarios"…
btnList.addEventListener('click', async () => {
  try {
    // Elegimos la función según el modo
    if (modeJwt.checked) await listUsersJWT();
    else                 await listUsersCookie();
  } catch (err) {
    // Si algo falla (red/JS), lo mostramos
    out.textContent = 'Error: ' + (err?.message || String(err));
  }
});

// Cuando se hace click en "Cambiar rol"…
btnChange.addEventListener('click', async () => {
  try {
    // Tomamos id y rol de los inputs
    const id   = parseInt(userId.value, 10);
    const role = newRole.value;

    // Elegimos la función según el modo
    if (modeJwt.checked) await changeRoleJWT(id, role);
    else                 await changeRoleCookie(id, role);
  } catch (err) {
    out.textContent = 'Error: ' + (err?.message || String(err));
  }
});

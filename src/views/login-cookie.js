// =====================================================
// Archivo: src/views/login-cookie.js
// Propósito: Hacer login con cookies y probar /me-cookie y logout.
// =====================================================

// Login con cookies (el server setea sid y csrfToken)
document.getElementById('form-login').addEventListener('submit', async (e) => {
  e.preventDefault(); // Evitar recarga

  const email = document.getElementById('email').value.trim(); // Email
  const password = document.getElementById('password').value;  // Password
  const result = document.getElementById('result');            // Salida

  try {
    // POST /login-cookie con credentials: 'include' para que el navegador acepte cookies
    const res = await fetch('/login-cookie', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',               // Necesario para cookies
      body: JSON.stringify({ email, password })
    });

    // Mostrar respuesta
    const text = await res.text();
    let out = text;
    try { out = JSON.stringify(JSON.parse(text), null, 2); } catch {}
    result.textContent = out;

  } catch (err) {
    result.textContent = 'Error: ' + err.message;
  }
});

// Probar /me-cookie (requiere estar logueado con cookies)
document.getElementById('btn-me').addEventListener('click', async () => {
  const result = document.getElementById('result');
  try {
    const res = await fetch('/me-cookie', { credentials: 'include' }); // Enviar cookies
    const text = await res.text();
    let out = text;
    try { out = JSON.stringify(JSON.parse(text), null, 2); } catch {}
    result.textContent = out;
  } catch (err) {
    result.textContent = 'Error: ' + err.message;
  }
});

// Cerrar sesión (revocar sesión server-side y limpiar cookies)
document.getElementById('btn-logout').addEventListener('click', async () => {
  const result = document.getElementById('result');
  try {
    const res = await fetch('/logout-cookie', {
      method: 'POST',
      credentials: 'include'
    });
    const text = await res.text();
    let out = text;
    try { out = JSON.stringify(JSON.parse(text), null, 2); } catch {}
    result.textContent = out;
  } catch (err) {
    result.textContent = 'Error: ' + err.message;
  }
});

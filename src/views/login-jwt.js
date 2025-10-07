// =====================================================
// Archivo: src/views/login-jwt.js
// Propósito: Hacer login JWT y probar /me-jwt usando Authorization.
// =====================================================

// Listener para el submit del login
document.getElementById('form-login').addEventListener('submit', async (e) => {
  e.preventDefault(); // Evitar recarga
  const email = document.getElementById('email').value.trim(); // Leer email
  const password = document.getElementById('password').value;   // Leer password
  const result = document.getElementById('result');             // Salida

  try {
    // POST /login-jwt
    const res = await fetch('/login-jwt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    // Parsear respuesta
    const data = await res.json().catch(() => null);
    if (data) {
      // Si hay token, lo ponemos en el textarea
      if (data.access_token) document.getElementById('token').value = data.access_token;
      result.textContent = JSON.stringify(data, null, 2);
    } else {
      // Si no era JSON, mostramos texto plano
      result.textContent = await res.text();
    }
  } catch (err) {
    result.textContent = 'Error: ' + err.message;
  }
});

// Listener para probar /me-jwt con Authorization: Bearer <token>
document.getElementById('btn-me').addEventListener('click', async () => {
  const token = document.getElementById('token').value.trim(); // Tomar token
  const result = document.getElementById('result');            // Salida

  try {
    // GET /me-jwt con header Authorization
    const res = await fetch('/me-jwt', {
      headers: { Authorization: `Bearer ${token}` }
    });

    // Mostrar resultado
    const text = await res.text();
    let out = text;
    try { out = JSON.stringify(JSON.parse(text), null, 2); } catch {}
    result.textContent = out;
  } catch (err) {
    result.textContent = 'Error: ' + err.message;
  }
});

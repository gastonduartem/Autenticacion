// =====================================================
// Archivo: src/views/register-cookie.js
// Propósito: Enviar registro a /register-cookie y mostrar respuesta.
// =====================================================

document.getElementById('form-register').addEventListener('submit', async (e) => {
  e.preventDefault(); // Evitar recarga

  // Tomar datos del form
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const role = document.getElementById('role').value;

  // Armar payload
  const payload = role ? { email, password, role } : { email, password };

  try {
    // Enviar POST; credentials: 'include' para permitir setear/leer cookies
    const res = await fetch('/register-cookie', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      credentials: 'include'
    });

    // Mostrar respuesta
    const text = await res.text();
    let out = text;
    try { out = JSON.stringify(JSON.parse(text), null, 2); } catch {}
    document.getElementById('result').textContent = out;

  } catch (err) {
    document.getElementById('result').textContent = 'Error: ' + err.message;
  }
});

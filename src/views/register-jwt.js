// =====================================================
// Archivo: src/views/register-jwt.js
// Propósito: Capturar envío del form y llamar a /register-jwt
//            con { email, password, role? }.
// =====================================================

// Adjuntamos un listener al envío del formulario
document.getElementById('form-register').addEventListener('submit', async (e) => {
  e.preventDefault(); // Evitamos que el form recargue la página

  // Leemos valores de los inputs
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const role = document.getElementById('role').value; // "" | "user" | "admin"

  // Construimos el payload: si role está vacío, no lo mandamos
  const payload = role ? { email, password, role } : { email, password };

  try {
    // Hacemos la request al backend
    const res = await fetch('/register-jwt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }, // Indicamos JSON
      body: JSON.stringify(payload)                    // Enviamos body
    });

    // Intentamos presentar la respuesta bonita (JSON si se puede)
    const text = await res.text();
    let out = text;
    try { out = JSON.stringify(JSON.parse(text), null, 2); } catch {}
    document.getElementById('result').textContent = out; // Pintamos resultado

  } catch (err) {
    // Si hubo error de red/JS, lo mostramos
    document.getElementById('result').textContent = 'Error: ' + err.message;
  }
});

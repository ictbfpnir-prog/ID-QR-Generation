document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(e.target).entries());
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  const result = await res.json();
  if (!res.ok) {
    const err = document.getElementById('error');
    err.textContent = result.error || 'Login failed';
    err.style.display = 'block';
    return;
  }
  window.location.href = '/admin.html';
});

// Gate the page on an active session before showing anything useful.
async function checkSession() {
  const res = await fetch('/api/session');
  const s = await res.json();
  if (!s.loggedIn) {
    window.location.href = '/login.html';
    return;
  }
  document.getElementById('whoami').textContent = `${s.username} (${s.role})`;
}

document.getElementById('logoutBtn').addEventListener('click', async () => {
  await fetch('/api/logout', { method: 'POST' });
  window.location.href = '/login.html';
});

const form = document.getElementById('personnelForm');

function readPhotoFile(fileInput) {
  return new Promise((resolve) => {
    const file = fileInput.files[0];
    if (!file) return resolve(null);
    const reader = new FileReader();
    reader.onload = () => {
      const [, base64] = reader.result.split(',');
      resolve({ base64, mimeType: file.type });
    };
    reader.readAsDataURL(file);
  });
}

function renderQrResult(idNumber, fullName, qr) {
  const label = fullName ? `QR generated for ${fullName}` : `QR for ${idNumber}`;
  document.getElementById('qrResult').innerHTML = `
    <h3>${label}</h3>
    <img src="${qr.qrDataUrl}" width="180" height="180"/>
    <p><a class="profile-link" href="${qr.profileUrl}" target="_blank" rel="noopener">${qr.profileUrl}</a></p>
  `;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(form).entries());
  delete data.photoFile;

  const photo = await readPhotoFile(form.photoFile);
  if (photo) {
    data.photoBase64 = photo.base64;
    data.photoMimeType = photo.mimeType;
  }

  const saveRes = await fetch('/api/personnel', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  if (saveRes.status === 401) { window.location.href = '/login.html'; return; }
  const saved = await saveRes.json();
  if (saved.error) { alert(saved.error); return; }

  const qrRes = await fetch(`/api/qr/${saved.idNumber}`);
  const qr = await qrRes.json();
  renderQrResult(saved.idNumber, data.fullName, qr);
  loadRecords();
});

async function loadRecords() {
  const res = await fetch('/api/personnel');
  if (res.status === 401) { window.location.href = '/login.html'; return; }
  const rows = await res.json();
  const tbody = document.querySelector('#recordsTable tbody');
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td>${r.id_number}</td>
      <td>${r.full_name}</td>
      <td>${r.rank}</td>
      <td>${r.unit_code || ''}</td>
      <td>${r.status}</td>
      <td><button class="view-qr-btn" data-id="${r.id_number}">View QR</button></td>
    </tr>
  `).join('');
}

async function viewQr(idNumber) {
  const qrRes = await fetch(`/api/qr/${idNumber}`);
  const qr = await qrRes.json();
  renderQrResult(idNumber, null, qr);
}

// Event delegation instead of inline onclick attributes (also CSP-blocked).
document.getElementById('recordsTable').addEventListener('click', (e) => {
  const btn = e.target.closest('.view-qr-btn');
  if (btn) viewQr(btn.dataset.id);
});

checkSession().then(loadRecords);

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const QRCode = require("qrcode");
const path = require("path");
const pool = require("./db");
const { sign, verify } = require("./utils/sign");
const { requireLogin, requireRole } = require("./utils/auth");

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is not set. Copy .env.example to .env and fill it in.");
}

app.use(helmet());
app.use(express.json({ limit: "8mb" }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === "true", // true only when actually served over HTTPS
    maxAge: 1000 * 60 * 60 * 8 // 8-hour session
  }
}));

// Rate limit: general API abuse prevention
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
app.use("/api/", apiLimiter);

// Tighter limit on login specifically, to slow down password guessing
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

// Tighter limit on public profile views, to slow down scraping/enumeration
const profileLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60 });

app.use(express.static(path.join(__dirname, "public")));

async function logScan(idNumber, role, ok, reason) {
  await pool.query(
    "INSERT INTO scan_log (id_number, role, result, reason) VALUES (?, ?, ?, ?)",
    [idNumber, role, ok ? "granted" : "denied", reason]
  );
}

// ======================= AUTH =======================

app.post("/api/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const [rows] = await pool.query(
    "SELECT * FROM admin_users WHERE username = ? AND is_active = TRUE",
    [username]
  );
  const user = rows[0];

  // Always run bcrypt.compare even on a missing user, using a dummy hash,
  // so response timing doesn't reveal whether the username exists.
  const hashToCheck = user ? user.password_hash : "$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinva";
  const passwordOk = await bcrypt.compare(password, hashToCheck);

  if (!user || !passwordOk) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  req.session.user = { id: user.id, username: user.username, role: user.role };
  await pool.query("UPDATE admin_users SET last_login_at = NOW() WHERE id = ?", [user.id]);

  res.json({ ok: true, username: user.username, role: user.role });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/session", (req, res) => {
  if (req.session && req.session.user) {
    return res.json({ loggedIn: true, username: req.session.user.username, role: req.session.user.role });
  }
  res.json({ loggedIn: false });
});

// ======================= ADMIN: personnel =======================

app.post("/api/personnel", requireRole("admin", "records_staff"), async (req, res) => {
  try {
    const {
      idNumber, rank, fullName, officerType, unitAssignment, unitCode,
      status, dateIssued, expiryDate,
      photoBase64, photoMimeType,
      dateOfBirth, bloodType, height, weight, eyes, hair, religion,
      homeAddress, tin, gsisNo, pagibigNo, philhealthNo, emergencyContact
    } = req.body;

    if (!idNumber || !rank || !fullName) {
      return res.status(400).json({ error: "idNumber, rank, and fullName are required" });
    }

    await pool.query(
      `INSERT INTO personnel
         (id_number, \`rank\`, full_name, officer_type, unit_assignment, unit_code, status, date_issued, expiry_date)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         \`rank\`=VALUES(\`rank\`), full_name=VALUES(full_name), officer_type=VALUES(officer_type),
         unit_assignment=VALUES(unit_assignment), unit_code=VALUES(unit_code), status=VALUES(status),
         date_issued=VALUES(date_issued), expiry_date=VALUES(expiry_date)`,
      [idNumber, rank, fullName, officerType || "Commissioned Officer", unitAssignment || null,
       unitCode || "BFP-NIR", status || "Active", dateIssued || null, expiryDate || null]
    );

    if (photoBase64 && photoMimeType) {
      const photoBuffer = Buffer.from(photoBase64, "base64");
      await pool.query(
        `INSERT INTO personnel_photo (id_number, mime_type, photo_blob)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE mime_type=VALUES(mime_type), photo_blob=VALUES(photo_blob)`,
        [idNumber, photoMimeType, photoBuffer]
      );
    }

    await pool.query(
      `INSERT INTO personnel_sensitive
         (id_number, date_of_birth, blood_type, height, weight, eyes, hair, religion, home_address, tin, gsis_no, pagibig_no, philhealth_no, emergency_contact)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         date_of_birth=VALUES(date_of_birth), blood_type=VALUES(blood_type), height=VALUES(height),
         weight=VALUES(weight), eyes=VALUES(eyes), hair=VALUES(hair), religion=VALUES(religion),
         home_address=VALUES(home_address), tin=VALUES(tin), gsis_no=VALUES(gsis_no),
         pagibig_no=VALUES(pagibig_no), philhealth_no=VALUES(philhealth_no), emergency_contact=VALUES(emergency_contact)`,
      [idNumber, dateOfBirth || null, bloodType || null, height || null, weight || null,
       eyes || null, hair || null, religion || null, homeAddress || null, tin || null,
       gsisNo || null, pagibigNo || null, philhealthNo || null, emergencyContact || null]
    );

    res.json({ ok: true, idNumber });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error while saving record" });
  }
});

app.get("/api/personnel", requireRole("admin", "records_staff"), async (req, res) => {
  const [rows] = await pool.query(
    "SELECT id_number, `rank`, full_name, officer_type, unit_assignment, unit_code, status FROM personnel ORDER BY updated_at DESC"
  );
  res.json(rows);
});

app.get("/api/personnel/:idNumber/full", requireRole("admin"), async (req, res) => {
  const { idNumber } = req.params;
  const [personRows] = await pool.query("SELECT * FROM personnel WHERE id_number = ?", [idNumber]);
  const [sensRows] = await pool.query("SELECT * FROM personnel_sensitive WHERE id_number = ?", [idNumber]);
  if (personRows.length === 0) return res.status(404).json({ error: "Unknown ID number" });
  await logScan(idNumber, "admin", true, `full record view by ${req.session.user.username}`);
  res.json({ ...personRows[0], ...(sensRows[0] || {}) });
});

app.get("/api/qr/:idNumber", requireRole("admin", "records_staff"), async (req, res) => {
  const { idNumber } = req.params;
  const [rows] = await pool.query("SELECT id_number FROM personnel WHERE id_number = ?", [idNumber]);
  if (rows.length === 0) return res.status(404).json({ error: "Unknown ID number" });

  const sig = sign(idNumber);
  const profileUrl = `${BASE_URL}/profiles/${idNumber}?sig=${sig}`;

  try {
    const qrDataUrl = await QRCode.toDataURL(profileUrl);
    res.json({ idNumber, profileUrl, qrDataUrl });
  } catch (err) {
    res.status(500).json({ error: "QR generation failed" });
  }
});

app.get("/api/audit-log", requireRole("admin"), async (req, res) => {
  const [rows] = await pool.query("SELECT * FROM scan_log ORDER BY scanned_at DESC LIMIT 200");
  res.json(rows);
});

// ======================= PUBLIC =======================

app.get("/photos/:idNumber", profileLimiter, async (req, res) => {
  const [rows] = await pool.query(
    "SELECT mime_type, photo_blob FROM personnel_photo WHERE id_number = ?",
    [req.params.idNumber]
  );
  if (rows.length === 0 || !rows[0].photo_blob) return res.status(404).send("No photo on file");
  res.set("Content-Type", rows[0].mime_type || "image/jpeg");
  res.send(rows[0].photo_blob);
});

app.get("/profiles/:idNumber", profileLimiter, async (req, res) => {
  const { idNumber } = req.params;
  const { sig } = req.query;

  if (!verify(idNumber, sig)) {
    await logScan(idNumber, "public", false, "invalid or tampered signature");
    return res.status(403).send(renderErrorPage("This QR code is invalid or has been tampered with."));
  }

  const [rows] = await pool.query("SELECT * FROM personnel WHERE id_number = ?", [idNumber]);
  if (rows.length === 0) {
    await logScan(idNumber, "public", false, "unknown ID number");
    return res.status(404).send(renderErrorPage("No record found for this ID."));
  }

  await logScan(idNumber, "public", true, "profile view");
  res.send(renderProfilePage(rows[0]));
});

function renderErrorPage(message) {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Verification Failed</title>
  <style>body{font-family:sans-serif;max-width:480px;margin:80px auto;text-align:center;color:#900}</style>
  </head><body><h2>⚠ Verification Failed</h2><p>${message}</p></body></html>`;
}

function renderProfilePage(p) {
  const statusColor = p.status === "Active" ? "#2e7d32" : "#b71c1c";
  const dateIssued = p.date_issued ? new Date(p.date_issued).toISOString().slice(0, 10) : "—";
  const expiryDate = p.expiry_date ? new Date(p.expiry_date).toISOString().slice(0, 10) : "—";
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>${p.full_name} - ${p.unit_code || "BFP"} Profile</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; background: #f2f4f7; margin: 0; padding: 24px; }
  .card { max-width: 420px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); padding: 20px 24px; }
  .header { display: flex; gap: 14px; align-items: flex-start; }
  .photo { width: 64px; height: 64px; border-radius: 8px; background: #dbe1e8 url('/photos/${p.id_number}') center/cover; flex-shrink: 0; }
  .rank { color: #1a3d8f; font-weight: 700; font-size: 0.85rem; letter-spacing: 0.02em; }
  .name { font-size: 1.15rem; font-weight: 800; color: #0d1b3e; margin: 2px 0 8px; }
  .badge { display: inline-block; background: #f5a623; color: #3a2600; font-weight: 700; font-size: 0.72rem;
           padding: 3px 10px; border-radius: 12px; margin-bottom: 8px; }
  .meta { color: #667; font-size: 0.85rem; }
  .status { color: ${statusColor}; font-weight: 600; }
  .status::before { content: "\\25CF "; }
  .section-title { text-transform: uppercase; font-size: 0.75rem; color: #1a3d8f; font-weight: 700;
                   letter-spacing: 0.05em; border-bottom: 1px solid #e3e6eb; padding-bottom: 6px; margin: 18px 0 10px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px 20px; }
  .label { font-size: 0.7rem; color: #8a94a6; text-transform: uppercase; letter-spacing: 0.03em; }
  .value { font-weight: 700; color: #17223b; font-size: 0.92rem; }
</style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="photo"></div>
      <div>
        <div class="rank">${p.rank}</div>
        <div class="name">${p.full_name}</div>
        <span class="badge">${p.officer_type}</span><br/>
        <span class="meta">ID No. ${p.id_number} &nbsp;&bull;&nbsp; ${p.unit_code || ""}</span><br/>
        <span class="status">${p.status}</span>
      </div>
    </div>
    <div class="section-title">Assignment</div>
    <div class="grid">
      <div><div class="label">Date Issued</div><div class="value">${dateIssued}</div></div>
      <div><div class="label">Expiry Date</div><div class="value">${expiryDate}</div></div>
      <div style="grid-column: 1 / -1;"><div class="label">Unit Assignment</div><div class="value">${p.unit_assignment || "—"}</div></div>
    </div>
  </div>
</body>
</html>`;
}

app.listen(PORT, () => {
  console.log(`BFP QR profile system running at ${BASE_URL}`);
});

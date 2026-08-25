# BFP-NIR QR Profile System — Final hardened version

This is the production-shaped version: real login (no more fake role
headers), rate limiting, security headers, and passwords stored properly
hashed. Same core design as before — QR encodes only a signed reference,
tiered data disclosure, photo and sensitive fields kept in separate
tables from the public-facing record.

## 1. Set up the database

```bash
mysql -u root -p < sql/mysql_schema.sql
```

This creates the `bfp_qr_system` database and all five tables, including
the new `admin_users` table.

## 2. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and fill in:
- Your real MySQL credentials
- `QR_SIGNING_SECRET` and `SESSION_SECRET` — generate each with:
  ```bash
  node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
  ```
  Use **two different** values — don't reuse one secret for both.
- Leave `COOKIE_SECURE=false` for local testing. Only set it to `true`
  once the app is actually served over HTTPS (see deployment notes
  below) — otherwise your browser will silently refuse to send the
  session cookie and login will appear to "not work."

## 3. Install dependencies

```bash
npm install
```

Nothing here needs native compilation (bcryptjs is pure JS specifically
to avoid the Visual Studio issue from earlier), so this should install
cleanly on Windows.

## 4. Create your first admin account

```bash
npm run seed-admin
```

This prompts for a username, password (minimum 10 characters), and role,
then stores a bcrypt hash in the database — never a plaintext password.
Run it again anytime to create additional accounts or reset a password.

## 5. Run it

```bash
npm start
```

Open `http://localhost:3000` — you'll land on the login page. Sign in
with the account you just created, and you're in the admin interface.

## What's actually different from the earlier prototypes

- **Real login.** `POST /api/login` checks a bcrypt-hashed password
  against the `admin_users` table and starts a signed session cookie.
  Every admin route (`/api/personnel`, `/api/qr/:idNumber`,
  `/api/personnel/:idNumber/full`, `/api/audit-log`) now requires that
  session — no more `X-Role` header that anyone could set themselves.
- **Two roles.** `admin` can see everything, including full sensitive
  records. `records_staff` can create/edit personnel and generate QR
  codes, but cannot pull the full sensitive record — adjust the
  `requireRole(...)` calls in `server.js` if your actual policy differs.
- **Rate limiting.** Login attempts are capped at 10 per 15 minutes per
  IP (slows down password guessing). Public profile/photo views are
  capped at 60 per 15 minutes per IP (slows down scraping every ID
  number in sequence).
- **Security headers** via `helmet` (sensible defaults: no MIME sniffing,
  no clickjacking via frame embedding, etc.).
- **Timing-safe login.** The login check runs `bcrypt.compare` even when
  the username doesn't exist, so response time doesn't leak which
  usernames are valid.
- **Sessions expire after 8 hours** and are stored in memory by default
  (fine for one server; see note below for multi-server deployment).

## What's still simplified — read before any real deployment

1. **Session store.** Sessions currently live in server memory
   (`express-session`'s default `MemoryStore`), which is fine for a
   single instance but won't survive a server restart and won't work if
   you ever run more than one instance behind a load balancer. For real
   deployment, use a proper session store — `connect-redis` is the
   standard choice.
2. **HTTPS is not handled by this code.** `COOKIE_SECURE=true` assumes
   you're behind a reverse proxy (nginx, Caddy, or your cloud provider's
   load balancer) that terminates TLS and forwards plain HTTP internally.
   This app does not generate or manage TLS certificates itself — that's
   a deployment/infrastructure step, not something to bolt on in Node.
3. **No account lockout after repeated failed logins** beyond the rate
   limiter — consider adding a lockout or CAPTCHA after N failed
   attempts for a given username if this becomes internet-facing.
4. **No password reset flow.** Currently `seed-admin.js` is also how you
   reset a forgotten password (run it again with the same username). A
   self-service reset flow (email-based) would need to be added
   separately, and needs its own careful design to avoid becoming a new
   attack surface.
5. **Photo storage at scale** — still BLOBs in MySQL, fine for a
   prototype/moderate headcount; move to object storage (S3/Cloud
   Storage) with a reference key for a large agency-wide rollout.
6. **This still needs BFP's IT security and data privacy office sign-off**
   before any real personnel record goes in — the Data Privacy Act
   requirements around TIN/GSIS/PAG-IBIG/PhilHealth numbers, addresses,
   and biometrics-adjacent photo data don't go away because the code is
   solid. Security engineering and compliance approval are separate
   things, and this project only covers the first one.

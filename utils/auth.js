// Blocks access unless a real login session exists (see server.js's
// POST /api/login, which sets req.session.user on success).
function requireLogin(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: "Login required" });
}

// Blocks access unless the logged-in user has the 'admin' role
// specifically (records_staff can view but not everything — adjust
// per-route as your policy requires).
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.session || !req.session.user) {
      return res.status(401).json({ error: "Login required" });
    }
    if (!allowedRoles.includes(req.session.user.role)) {
      return res.status(403).json({ error: "Insufficient permissions" });
    }
    next();
  };
}

module.exports = { requireLogin, requireRole };

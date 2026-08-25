const crypto = require("crypto");

const SECRET = process.env.QR_SIGNING_SECRET;
if (!SECRET) {
  throw new Error("QR_SIGNING_SECRET is not set. Copy .env.example to .env and fill it in.");
}

function sign(idNumber) {
  return crypto.createHmac("sha256", SECRET).update(idNumber).digest("hex").slice(0, 16);
}

function verify(idNumber, sig) {
  const expected = sign(idNumber);
  const a = Buffer.from(expected);
  const b = Buffer.from(sig || "");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

module.exports = { sign, verify };

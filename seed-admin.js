require("dotenv").config();
const bcrypt = require("bcryptjs");
const pool = require("./db");
const readline = require("readline");

function ask(question, hidden = false) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function main() {
  console.log("=== BFP QR System — Create/Reset Admin Account ===");
  const username = (await ask("Username: ")).trim();
  const password = await ask("Password (min 10 characters): ");
  const roleInput = (await ask("Role [admin/records_staff] (default: admin): ")).trim();
  const role = roleInput === "records_staff" ? "records_staff" : "admin";

  if (!username || password.length < 10) {
    console.error("Username required and password must be at least 10 characters. Aborting.");
    process.exit(1);
  }

  const passwordHash = await bcrypt.hash(password, 12);

  await pool.query(
    `INSERT INTO admin_users (username, password_hash, role)
     VALUES (?, ?, ?)
     ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), role = VALUES(role), is_active = TRUE`,
    [username, passwordHash, role]
  );

  console.log(`Account "${username}" (${role}) created/updated successfully.`);
  process.exit(0);
}

main().catch((err) => {
  console.error("Failed to create admin account:", err.message);
  process.exit(1);
});

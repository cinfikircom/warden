// Bilerek açıklı fixture — yalnızca test amaçlı. Üretimde KULLANMA.
const jwt = require("jsonwebtoken");

// B4-weak-jwt-secret-config: sözlük secret'ı yapılandırmada.
const JWT_SECRET = "changeme";

// B4-weak-jwt-secret: sözlük secret'ı doğrudan imzalamada.
function issue(user) {
  return jwt.sign({ sub: user.id }, "secret", { expiresIn: "1h" });
}

module.exports = { issue, JWT_SECRET };

const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const router = express.Router();

// No rate limiting / lockout anywhere (AUTH-5), no MFA (AUTH-1).
router.post("/login", async (req, res) => {
  const user = await findUser(req.body.email);
  const ok = await bcrypt.compare(req.body.password, user.hash);
  if (!ok) return res.status(401).end();

  // AUTH-4: JWT signed with NO expiry → stolen token valid forever.
  const token = jwt.sign({ sub: user.id }, process.env.JWT_SECRET);

  // AUTH-3: session cookie without httpOnly/secure.
  res.cookie("token", token, { httpOnly: false, secure: false });
  res.json({ ok: true });
});

router.post("/register", async (req, res) => {
  // AUTH-6: password hashed, but no strength / pwned-password policy checked.
  const hash = await bcrypt.hash(req.body.password, 10);
  await createUser(req.body.email, hash);
  res.json({ ok: true });
});

router.post("/forgot-password", async (req, res) => {
  // AUTH-2: predictable reset token (Math.random + Date.now, not crypto-random).
  const resetToken = Math.random().toString(36).slice(2) + Date.now();
  await saveResetToken(req.body.email, resetToken);
  res.json({ ok: true });
});

module.exports = router;

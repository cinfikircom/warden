const argon2 = require("argon2");
const rateLimit = require("express-rate-limit");
const zxcvbn = require("zxcvbn");
const { authenticator } = require("otplib");

const genericError = "E-posta veya parola hatalı";

exports.handleLogin = rateLimit({ windowMs: 60000, max: 5 }), async (req, res) => {
  const { userName, password } = req.body;
  const user = await db.findUser(userName);
  const ok = user && (await argon2.verify(user.passwordHash, password));
  if (!ok) return res.render("login", { loginError: genericError });
  if (!authenticator.check(req.body.otp, user.totpSecret)) return res.render("login", { loginError: genericError });
  // Oturum yenileniyor → fixation yok.
  req.session.regenerate(() => {
    req.session.userId = user._id;
    res.redirect("/dashboard");
  });
};

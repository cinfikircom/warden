const express = require("express");
const session = require("express-session");
const cors = require("cors");

const app = express();
app.use(express.json());

// Çerez-tabanlı oturum — CSRF alakalı ama hiçbir CSRF koruması yok (WEB-1).
app.use(session({ secret: "keyboard-cat", resave: false, saveUninitialized: true }));

// WEB-3: istek origin'i yansıtılıyor + credentials açık → herkese kimlikli erişim.
app.use(cors({ origin: true, credentials: true }));

// Not: helmet / X-Frame-Options / HSTS / CSP hiçbir yerde yok (WEB-2).

// State-değiştiren route'lar, CSRF token doğrulaması yok (WEB-1).
app.post("/account/email", (req, res) => {
  req.session.user.email = req.body.email;
  res.json({ ok: true });
});

app.put("/account/password", (req, res) => {
  req.session.user.password = req.body.password;
  res.json({ ok: true });
});

app.delete("/account", (req, res) => {
  res.json({ ok: true });
});

app.listen(3000);

const express = require("express");
const nodemailer = require("nodemailer");
const router = express.Router();

// EMAIL-3: SMTP TLS'siz — secure:false + port 25, kimlik bilgisi ve içerik açıkta.
const transport = nodemailer.createTransport({
  host: "smtp.example.com",
  port: 25,
  secure: false,
});

router.post("/contact", async (req, res) => {
  await transport.sendMail({
    to: "support@example.com",
    // EMAIL-1: kullanıcı girdisi from + replyTo başlıklarında (CRLF header injection).
    from: req.body.from,
    replyTo: req.body.email,
    subject: "İletişim formu",
    // EMAIL-2: HTML gövdesine kaçışsız kullanıcı girdisi (phishing/içerik enjeksiyonu).
    html: `<p>Mesaj: ${req.body.message}</p><p>Ad: ${req.body.name}</p>`,
  });
  res.json({ ok: true });
});

module.exports = router;

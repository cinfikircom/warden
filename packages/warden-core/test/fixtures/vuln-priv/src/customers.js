const express = require("express");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const router = express.Router();

router.post("/customers", async (req, res) => {
  const customer = await prisma.customer.create({ data: {
    email: req.body.email, phone: req.body.phone, tckimlik: req.body.tckimlik, iban: req.body.iban,
  } });

  // PRIV-1: personal data written straight to the log.
  console.log("created customer", customer.email, customer.tckimlik, customer.iban);

  // PRIV-2: personal data placed in a URL / query string.
  const verifyLink = `https://app.example.com/verify?email=${customer.email}&token=abc`;
  await sendEmail(customer.email, verifyLink);

  res.json({ id: customer.id });
});

module.exports = router;

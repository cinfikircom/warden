const express = require("express");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const router = express.Router();

// Uses auth → establishes the project DOES authenticate (so ACC-2 flags routes that don't).
router.get("/me", requireAuth, async (req, res) => {
  res.json(req.user);
});

// ACC-1: fetch by client-supplied id with NO tenant filter → cross-tenant data leak.
router.get("/invoices/:id", requireAuth, async (req, res) => {
  const invoice = await prisma.invoice.findUnique({ where: { id: req.params.id } });
  res.json(invoice);
});

// ACC-3: mass assignment — the whole request body is written straight to the model.
router.post("/profile", requireAuth, async (req, res) => {
  const user = await prisma.user.update({ where: { id: req.user.id }, data: req.body });
  res.json(user);
});

module.exports = router;

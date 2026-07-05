const express = require("express");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const db = require("./db");
const router = express.Router();

// No rate-limit middleware anywhere → API-2.
router.get("/reports", async (req, res) => {
  // API-1: SELECT * returns every column (incl. sensitive ones).
  const rows = await db.query("SELECT * FROM invoices");
  res.json(rows);
});

router.get("/users", async (req, res) => {
  try {
    // API-3: findMany with no take/limit → returns the entire table.
    const users = await prisma.user.findMany();
    res.json(users);
  } catch (err) {
    // API-4: raw stack trace leaked to the client.
    res.status(500).json({ error: err.stack });
  }
});

module.exports = router;

const express = require("express");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const router = express.Router();

// ACC-2: a state-changing route with NO auth middleware in this file
// (the rest of the app authenticates — this one was forgotten).
router.post("/comments", async (req, res) => {
  const c = await prisma.comment.create({ data: { text: req.body.text } });
  res.json(c);
});

module.exports = router;

const express = require("express");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const router = express.Router();

// ACC-4: privileged action — authenticated, but NO role check, so ANY logged-in
// user can promote themselves. (authz != authn)
router.post("/admin/set-role", requireAuth, async (req, res) => {
  await prisma.user.update({ where: { id: req.body.userId }, data: { role: req.body.role } });
  res.json({ ok: true });
});

module.exports = router;

const express = require("express");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const router = express.Router();

// FLOW-1: para transferi iki ayrı yazma, transaction yok — yarıda kesilirse para buharlaşır.
router.post("/transfer", async (req, res) => {
  const { fromId, toId, amount } = req.body;
  await prisma.account.update({ where: { id: fromId }, data: { balance: { decrement: amount } } });
  // kesinti burada olursa: borç düşüldü ama alacak yazılmadı
  await prisma.account.update({ where: { id: toId }, data: { balance: { increment: amount } } });
  res.json({ ok: true });
});

// FLOW-2: stok oku-değiştir-yaz, atomik değil — eşzamanlı siparişte fazla satış.
router.post("/order", async (req, res) => {
  const product = await prisma.product.findUnique({ where: { id: req.body.productId } });
  product.stock = product.stock - req.body.qty;
  await prisma.product.update({ where: { id: product.id }, data: { stock: product.stock } });

  // FLOW-3: sipariş oluşturma idempotent değil — çift tıklama = çift sipariş.
  await prisma.order.create({ data: { productId: product.id, qty: req.body.qty, userId: req.body.userId } });

  res.json({ ok: true });
});

module.exports = router;

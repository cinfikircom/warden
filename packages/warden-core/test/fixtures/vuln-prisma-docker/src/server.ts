// KASITLI açıklı sunucu yapılandırması (test fixture'ı).
import express from "express";
import cors from "cors";

const app = express();

app.use(cors({ origin: "*" }));

app.get("/users/:id", async (req, res) => {
  // IDOR adayı: sahiplik kontrolü yok.
  const user = await prisma.user.findUnique({ where: { id: req.params.id } });
  res.json(user);
});

app.use((err: any, _req: any, res: any, _next: any) => {
  res.status(500).json({ error: err.stack });
});

declare const prisma: any;
export default app;

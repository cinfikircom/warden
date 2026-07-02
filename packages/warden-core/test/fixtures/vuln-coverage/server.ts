// Kapsam-genişletme fixture'ı — bilerek açıklı (test amaçlı). Üretimde KULLANMA.
import axios from "axios";
import fs from "node:fs";
import jwt from "jsonwebtoken";
import serialize from "node-serialize";

export async function proxy(req: any, res: any) {
  // SSRF: hedef URL istemci girdisinden
  const r = await axios.get(req.query.url);
  return res.send(r.data);
}

export function download(req: any, res: any) {
  // Path traversal: dosya yolu istemci girdisinden
  const data = fs.readFileSync(req.params.file);
  res.send(data);
}

export function goto(req: any, res: any) {
  // Open redirect
  res.redirect(req.query.next);
}

export function load(input: string) {
  // Güvensiz deserialization
  return serialize.unserialize(input);
}

export function verify(token: string) {
  // JWT algorithm none
  return jwt.verify(token, "k", { algorithms: ["none"] });
}

export function headers(res: any) {
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'");
}

// Yüksek-entropili sabit secret
const apiKey = "aGVsbG8td29ybGQtdGhpcy1pcy1hLXJhbmRvbS1zZWNyZXQtdG9rZW4";
// Sağlayıcı anahtarı (Stripe canlı)
const stripeKey = "sk_live_4eC39HqLyjWDarjtT1zdp7dcAbCdEf00";

export { apiKey, stripeKey };

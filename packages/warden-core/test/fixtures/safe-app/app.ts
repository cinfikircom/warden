// Güvenli referans fixture'ı — desenlere yüzeyden benzer ama GÜVENLİ. Bulgu üretmemeli (FP muhafızı).
import axios from "axios";
import fs from "node:fs";

const API_BASE = "https://api.example.com/v1";
const apiKey = process.env.API_KEY ?? ""; // env'den; sabit değil
const placeholderToken = "xxxxxxxxxxxxxxxxxxxxxxxx"; // belirgin placeholder

export async function getStatus() {
  // Sabit, güvenli URL — kullanıcı girdisi yok
  const r = await axios.get(`${API_BASE}/status`);
  return r.data;
}

export function readConfig() {
  // Sabit yol — kullanıcı girdisi yok
  return fs.readFileSync("./config/app.json", "utf8");
}

export function query(db: any, userId: string) {
  // Parametreli sorgu — birleştirme yok
  return db.query("SELECT * FROM users WHERE id = $1", [userId]);
}

export { apiKey, placeholderToken };

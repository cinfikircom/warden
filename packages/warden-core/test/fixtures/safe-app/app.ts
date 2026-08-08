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

// ---- v0.10 kuralları için FP muhafızı ------------------------------------
// Aşağıdakiler yeni B6/B3/B4 kurallarının desenlerine YÜZEYDEN benzer ama güvenlidir.
// Bu blok bulgu üretirse regex fazla geniş demektir — kuralı daralt, testi gevşetme.

export function findUser(User: any, req: any) {
  // Cast edilmiş değer — {"$ne":null} operatör enjeksiyonu imkânsız
  return User.findOne({ email: String(req.body.email) });
}

export function encrypt(key: Buffer, plaintext: string) {
  // Çağrı başına rastgele IV; şifreli metnin başına eklenir
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([iv, cipher.update(plaintext), cipher.final()]);
}

export function issueToken(jwt: any, sub: string) {
  // Secret env'den; algoritma açıkça belirtilmiş; kısa TTL
  return jwt.sign({ sub }, process.env.JWT_SECRET as string, { algorithm: "HS256", expiresIn: "15m" });
}

export function ldapFind(client: any, filters: any, uid: string, cb: unknown) {
  // Parametreli filtre nesnesi — string birleştirme yok
  const filter = new filters.EqualityFilter({ attribute: "uid", value: uid });
  return client.search("ou=users,dc=example,dc=com", { filter }, cb);
}

export { apiKey, placeholderToken };

// Güvenli: iç grup ayrı bir karakter sınıfıyla (`\.`) ayrılmış — backtracking patlamaz.
export const SURUM_RE = /SURUM\s*([\d]+(?:\.[\d]+)*)/i;

// KASITLI olarak açıklı dosya (test fixture'ı). Gerçek kullanım için DEĞİL.
import crypto from "node:crypto";
import CryptoJS from "crypto-js";
import jwt from "jsonwebtoken";

const API_KEY = "sk-1234567890abcdef1234567890";

export function weakHashPassword(pw: string): string {
  return crypto.createHash("md5").update(pw).digest("hex");
}

export function encrypt(data: string): string {
  return CryptoJS.AES.encrypt(data, "secret-passphrase").toString();
}

export function makeResetToken(): string {
  return "reset-" + Math.random().toString(36).slice(2);
}

export function signSession(userId: string): string {
  return jwt.sign({ userId }, API_KEY, { expiresIn: "365d" });
}

export function getUserByIdRaw(db: { query: (s: string) => unknown }, id: string): unknown {
  return db.query("SELECT * FROM users WHERE id = '" + id + "'");
}

export function runReport(child: { exec: (s: string) => void }, name: string): void {
  child.exec("generate-report " + name);
}

export function unsafeParse(input: string): unknown {
  return eval("(" + input + ")");
}

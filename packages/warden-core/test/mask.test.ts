import { describe, it, expect } from "vitest";
import { maskSecrets, maskValue, looksLikeSecret } from "../src/secret/mask.ts";

describe("secret maskeleme (§2.4)", () => {
  it("key=value gizli alanı maskeler", () => {
    const out = maskSecrets('password="superGizli12345"');
    expect(out).not.toContain("superGizli12345");
    expect(out).toContain("***");
  });

  it("SECRET_KEY/DB_PASSWORD gibi alt çizgili anahtarları maskeler (regresyon)", () => {
    const out = maskSecrets("SECRET_KEY=supergizli12345");
    expect(out).not.toContain("supergizli12345");
    const out2 = maskSecrets("DB_PASSWORD=cokGizliParola");
    expect(out2).not.toContain("cokGizliParola");
  });

  it("JWT'yi maskeler", () => {
    const jwt = "eyJhbGciOiJIUzI1NiUUUU.eyJzdWIiOiIxMjM0NTY3ODkw.SflKxwRJSMeKKF2QT4fwpM";
    const out = maskSecrets(`token ${jwt}`);
    expect(out).not.toContain(jwt);
  });

  it("bağlantı dizesi parolasını maskeler", () => {
    const out = maskSecrets("postgres://user:gizliParola@db:5432/app");
    expect(out).not.toContain("gizliParola");
    expect(out).toContain("postgres://user:***@");
  });

  it("kısa değer tamamen maskelenir", () => {
    expect(maskValue("abc")).toBe("***");
  });

  it("uzun değerin yalnızca uçları görünür", () => {
    const m = maskValue("abcdefghijklmnop");
    expect(m.startsWith("ab")).toBe(true);
    expect(m.endsWith("op")).toBe(true);
    expect(m).toContain("***");
  });

  it("secret tespiti çalışır", () => {
    expect(looksLikeSecret("AKIA1234567890ABCDEF")).toBe(true);
    expect(looksLikeSecret("sıradan bir cümle")).toBe(false);
  });
});

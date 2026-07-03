import { describe, it, expect } from "vitest";
import { shannonEntropy, extractStringLiterals, looksHighEntropySecret } from "../src/util/entropy.ts";

describe("Shannon entropi", () => {
  it("tekrarlı string düşük, rastgele string yüksek entropi verir", () => {
    expect(shannonEntropy("aaaaaaaa")).toBeLessThan(1);
    expect(shannonEntropy("aGVsbG8td29ybGQtc2VjcmV0LXRva2Vu")).toBeGreaterThan(3.5);
  });
  it("boş string → 0", () => {
    expect(shannonEntropy("")).toBe(0);
  });
});

describe("string literal çıkarımı", () => {
  it("tek/çift/backtick tırnaklı değerleri çıkarır", () => {
    const lits = extractStringLiterals(`const a = "foo"; const b = 'bar'; const c = \`baz\`;`);
    expect(lits).toContain("foo");
    expect(lits).toContain("bar");
    expect(lits).toContain("baz");
  });
});

describe("looksHighEntropySecret", () => {
  it("secret anahtarına atanmış yüksek-entropili değeri yakalar", () => {
    expect(looksHighEntropySecret(`const apiKey = "aGVsbG8td29ybGQtdGhpcy1pcy1yYW5kb20tc2VjcmV0"`)).toBe(true);
  });
  it("secret ipucu olmayan satırı işaretlemez", () => {
    expect(looksHighEntropySecret(`const label = "aGVsbG8td29ybGQtdGhpcy1pcy1yYW5kb20"`)).toBe(false);
  });
  it("placeholder/env değerlerini eler (FP önleme)", () => {
    expect(looksHighEntropySecret(`const apiKey = "xxxxxxxxxxxxxxxxxxxxxxxx"`)).toBe(false);
    expect(looksHighEntropySecret(`const token = "your-token-goes-here-placeholder"`)).toBe(false);
    expect(looksHighEntropySecret(`const secret = process.env.SECRET`)).toBe(false);
  });
  it("kısa değerleri eler", () => {
    expect(looksHighEntropySecret(`const secret = "abc123"`)).toBe(false);
  });
});

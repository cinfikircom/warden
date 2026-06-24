import { describe, it, expect } from "vitest";
import { enrichRisk, scoreOf } from "../src/risk/score.ts";
import { buildAsvsChecklist, violatedAsvsCodes } from "../src/risk/asvs.ts";
import { makeFinding } from "../src/util/finding.ts";
import type { Finding } from "../src/model/finding.ts";

function f(id: string, severity: Finding["severity"], references?: string[]): Finding {
  return makeFinding({
    id, title: id, severity, module: "B", check: "B0", category: "x", confidence: "high",
    evidence: [{ type: "file", source: "x.ts", location: "1" }],
    impact: "i", recommendation: "r", effort: "S", autoFixable: false,
    ...(references ? { references } : {}),
  });
}

describe("CVSS v4 risk motoru", () => {
  it("SQL injection ~9.8 high", () => {
    const r = scoreOf(f("B6-sql-concat:x:1", "P0"));
    expect(r.cvss).toBeGreaterThanOrEqual(9);
    expect(r.exploitability).toBe("high");
  });

  it("JWT localStorage ~6.5 medium", () => {
    expect(scoreOf(f("FE-jwt-localstorage:x:1", "P1")).cvss).toBe(6.5);
  });

  it("bilinmeyen id → severity fallback", () => {
    expect(scoreOf(f("ZZ-unknown", "P2")).cvss).toBe(4.5);
  });

  it("enrichRisk tüm bulgulara cvss + exploitability ekler", () => {
    const out = enrichRisk([f("B6-eval:x:1", "P1"), f("ZZ", "P3")]);
    expect(out.every((x) => typeof x.cvss === "number")).toBe(true);
    expect(out.every((x) => x.exploitability)).toBe(true);
  });

  it("modülün verdiği cvss korunur", () => {
    const withCvss = { ...f("B6-eval:x:1", "P1"), cvss: 3.3 };
    expect(enrichRisk([withCvss])[0]?.cvss).toBe(3.3);
  });
});

describe("OWASP ASVS checklist", () => {
  it("referanstaki ASVS kodu ihlal olarak işaretlenir", () => {
    const codes = violatedAsvsCodes([f("a", "P1", ["OWASP A02:2021", "ASVS 6.2.3"])]);
    expect(codes.has("6.2.3")).toBe(true);
  });

  it("ASVS 6.2.3 → izlenen 6.2 kontrolü ✖ fail (ön-ek eşleşmesi)", () => {
    const list = buildAsvsChecklist([f("a", "P1", ["ASVS 6.2.3"])]);
    expect(list.items.find((i) => i.control === "ASVS 6.2")?.status).toBe("fail");
  });

  it("ihlal yoksa unknown (pass iddia edilmez)", () => {
    const list = buildAsvsChecklist([f("a", "P1")]);
    expect(list.items.every((i) => i.status === "unknown")).toBe(true);
  });
});

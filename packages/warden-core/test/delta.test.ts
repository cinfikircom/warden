import { describe, it, expect } from "vitest";
import { computeDelta } from "../src/report/delta.ts";
import type { PreviousRun } from "../src/report/delta.ts";
import { makeFinding } from "../src/util/finding.ts";
import type { Finding } from "../src/model/finding.ts";

function f(id: string, check: string, loc: string): Finding {
  return makeFinding({
    id, title: `bulgu ${id}`, severity: "P1", module: "B", check, category: "x",
    confidence: "high", evidence: [{ type: "file", source: loc, location: "1" }],
    impact: "i", recommendation: "r", effort: "S", autoFixable: false,
  });
}

describe("run-to-run delta (öncesi/sonrası)", () => {
  it("ilk çalışma → hepsi introduced", () => {
    const d = computeDelta(null, [f("a", "B3", "x.ts"), f("b", "B6", "y.ts")]);
    expect(d.isFirstRun).toBe(true);
    expect(d.introduced).toHaveLength(2);
    expect(d.fixed).toHaveLength(0);
  });

  it("düzeltilen / yeni / kalan doğru ayrışır", () => {
    const prevFindings = [f("a", "B3", "x.ts"), f("b", "B6", "y.ts")];
    const previous: PreviousRun = { findings: prevFindings, overallScore: 5, parityScore: 6, generatedAt: "2026-06-01" };
    // 'a' düzeltildi, 'b' kaldı, 'c' yeni geldi.
    const current = [f("b", "B6", "y.ts"), f("c", "B7", "z.ts")];
    const d = computeDelta(previous, current);
    expect(d.isFirstRun).toBe(false);
    expect(d.fixed.map((x) => x.id)).toEqual(["a"]);
    expect(d.persisting.map((x) => x.id)).toEqual(["b"]);
    expect(d.introduced.map((x) => x.id)).toEqual(["c"]);
  });

  it("aynı bulgu farklı konumda → farklı fingerprint (yeni sayılır)", () => {
    const previous: PreviousRun = { findings: [f("a", "B3", "x.ts")], overallScore: 5, parityScore: null, generatedAt: "t" };
    const d = computeDelta(previous, [f("a", "B3", "DIFFERENT.ts")]);
    expect(d.fixed).toHaveLength(1);
    expect(d.introduced).toHaveLength(1);
  });
});

import { describe, it, expect } from "vitest";
import { buildFindingPrompt, renderFindingPromptMd } from "../src/report/prompt.ts";
import { makeFinding } from "../src/util/finding.ts";
import type { Finding } from "../src/model/finding.ts";

function f(overrides: Partial<Parameters<typeof makeFinding>[0]> = {}): Finding {
  return makeFinding({
    id: "B3-weak-hash", title: "Zayıf hash kullanımı", severity: "P0", module: "B", check: "B3",
    category: "crypto", confidence: "high",
    evidence: [{ type: "file", source: "src/auth.ts", location: "42" }],
    impact: "Şifreler kırılabilir hash ile saklanıyor.",
    recommendation: "bcrypt/argon2'e geç.",
    effort: "M", autoFixable: false,
    ...overrides,
  });
}

describe("buildFindingPrompt", () => {
  it("temel alanları eşler", () => {
    const p = buildFindingPrompt(f());
    expect(p.id).toBe("B3-weak-hash");
    expect(p.severity).toBe("P0");
    expect(p.category).toBe("crypto");
    expect(p.check).toBe("B3");
    expect(p.locations).toEqual(["src/auth.ts:42"]);
    expect(p.recommendation).toBe("bcrypt/argon2'e geç.");
    expect(p.autoFixable).toBe(false);
    expect(p.effort).toBe("M");
  });

  it("CVSS varsa risk metnine yansır, yoksa severity'ye düşer", () => {
    // exploitability, FindingInput'ta değil (risk motorunun sonradan eklediği alan) — Finding'e doğrudan bindir.
    const withRisk: Finding = { ...f({ cvss: 8.1 }), exploitability: "high" };
    expect(buildFindingPrompt(withRisk).risk).toBe("CVSS 8.1 / exploitability high");
    expect(buildFindingPrompt(f()).risk).toBe("P0");
  });

  it("kanıt yoksa locations boş dizi olur", () => {
    expect(buildFindingPrompt(f({ evidence: [] })).locations).toEqual([]);
  });

  it("references yoksa standards boş dizi olur", () => {
    expect(buildFindingPrompt(f()).standards).toEqual([]);
    expect(buildFindingPrompt(f({ references: ["OWASP A02:2021"] })).standards).toEqual(["OWASP A02:2021"]);
  });
});

describe("renderFindingPromptMd", () => {
  it("fenced text bloğu üretir, konum yoksa yer tutucu kullanır", () => {
    const md = renderFindingPromptMd(buildFindingPrompt(f({ evidence: [] })));
    expect(md.startsWith("```text\n")).toBe(true);
    expect(md.endsWith("```")).toBe(true);
    expect(md).toContain("  - (rapora bakın)");
  });

  it("konum(lar)ı listeler", () => {
    const md = renderFindingPromptMd(buildFindingPrompt(f()));
    expect(md).toContain("  - src/auth.ts:42");
    expect(md).toContain("Bulgu: Zayıf hash kullanımı");
    expect(md).toContain("bulgu (`B3-weak-hash`) \"düzeltilen\"e geçmeli");
  });
});

import { describe, it, expect } from "vitest";
import { parseKev, parseEpss, enrichKevEpss, cvesOfFinding } from "../src/risk/kev.ts";
import { makeFinding } from "../src/util/finding.ts";
import type { Finding } from "../src/model/finding.ts";

function depFinding(cve: string): Finding {
  return makeFinding({
    id: `B2-osv:django:GHSA-x`,
    title: "Zafiyetli bağımlılık: django",
    severity: "P1",
    module: "B",
    check: "B2",
    category: "Vulnerable Component",
    confidence: "high",
    evidence: [{ type: "command", source: "osv", excerpt: "django zafiyeti" }],
    impact: "x",
    recommendation: "y",
    effort: "S",
    autoFixable: true,
    references: ["OSV", cve],
    cves: [cve],
  });
}

describe("KEV feed ayrıştırma", () => {
  it("CISA KEV ham feed şeklini ayrıştırır", () => {
    const set = parseKev(JSON.stringify({ vulnerabilities: [{ cveID: "CVE-2021-44228" }, { cveID: "CVE-2022-1388" }] }));
    expect(set.has("CVE-2021-44228")).toBe(true);
    expect(set.size).toBe(2);
  });
  it("düz CVE listesini ayrıştırır", () => {
    const set = parseKev(JSON.stringify(["CVE-2021-44228"]));
    expect(set.has("CVE-2021-44228")).toBe(true);
  });
  it("bozuk girdi → boş küme", () => {
    expect(parseKev("nope").size).toBe(0);
  });
});

describe("EPSS ayrıştırma", () => {
  it("FIRST API şeklini ({data:[{cve,epss}]}) ayrıştırır", () => {
    const m = parseEpss(JSON.stringify({ data: [{ cve: "CVE-2021-44228", epss: "0.97" }] }));
    expect(m.get("CVE-2021-44228")).toBeCloseTo(0.97);
  });
  it("düz harita şeklini ayrıştırır", () => {
    const m = parseEpss(JSON.stringify({ "CVE-2022-1388": 0.6 }));
    expect(m.get("CVE-2022-1388")).toBeCloseTo(0.6);
  });
});

describe("enrichKevEpss", () => {
  it("KEV eşleşmesinde kev=true + exploitability high + referans ekler", () => {
    const kev = new Set(["CVE-2021-44228"]);
    const [f] = enrichKevEpss([depFinding("CVE-2021-44228")], kev, new Map());
    expect(f?.kev).toBe(true);
    expect(f?.exploitability).toBe("high");
    expect(f?.references?.some((r) => r.includes("KEV"))).toBe(true);
  });
  it("yüksek EPSS (≥0.5) exploitability'yi yükseltir", () => {
    const epss = new Map([["CVE-2022-1388", 0.8]]);
    const [f] = enrichKevEpss([depFinding("CVE-2022-1388")], new Set(), epss);
    expect(f?.epss).toBeCloseTo(0.8);
    expect(f?.exploitability).toBe("high");
  });
  it("KEV/EPSS eşleşmeyen bulguyu değiştirmez", () => {
    const [f] = enrichKevEpss([depFinding("CVE-2000-0001")], new Set(["CVE-2021-44228"]), new Map());
    expect(f?.kev).toBeUndefined();
  });
  it("veri boşsa bulguları olduğu gibi döndürür", () => {
    const input = [depFinding("CVE-2021-44228")];
    expect(enrichKevEpss(input, new Set(), new Map())).toHaveLength(1);
  });
});

describe("cvesOfFinding", () => {
  it("referans/kanıt/id'den CVE toplar", () => {
    expect(cvesOfFinding(depFinding("CVE-2021-44228"))).toContain("CVE-2021-44228");
  });
});

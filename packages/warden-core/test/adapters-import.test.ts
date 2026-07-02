import { describe, it, expect } from "vitest";
import { sarifToFindings } from "../src/adapters/sarif.ts";
import { osvToFindings } from "../src/adapters/osv.ts";

describe("SARIF 2.1.0 → Finding normalizasyonu", () => {
  const sarif = JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "semgrep",
            rules: [
              {
                id: "javascript.express.sqli",
                properties: { "security-severity": "9.1", tags: ["CWE-89", "OWASP A03:2021"] },
              },
            ],
          },
        },
        results: [
          {
            ruleId: "javascript.express.sqli",
            level: "error",
            message: { text: "SQL injection via string concat (CVE-2023-1234)" },
            locations: [
              { physicalLocation: { artifactLocation: { uri: "src/db.js" }, region: { startLine: 42 } } },
            ],
          },
        ],
      },
    ],
  });

  const findings = sarifToFindings(sarif);

  it("sonucu bulguya çevirir, security-severity→P0", () => {
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("P0");
  });
  it("araç adı, kural, konum ve referansları taşır", () => {
    const f = findings[0]!;
    expect(f.title).toContain("semgrep");
    expect(f.evidence[0]?.source).toBe("src/db.js");
    expect(f.evidence[0]?.location).toBe("42");
    expect(f.references).toContain("CWE-89");
  });
  it("mesajdan CVE çıkarır (KEV/EPSS eşleştirmesi için)", () => {
    expect(findings[0]?.cves).toContain("CVE-2023-1234");
  });
  it("level fallback: warning→P2, note→P3", () => {
    const mk = (level: string) =>
      sarifToFindings(
        JSON.stringify({
          runs: [{ tool: { driver: { name: "t" } }, results: [{ ruleId: "r", level, message: { text: "x" }, locations: [] }] }],
        }),
      )[0]?.severity;
    expect(mk("warning")).toBe("P2");
    expect(mk("note")).toBe("P3");
  });
  it("bozuk/boş girdi → [] (fırlatmaz)", () => {
    expect(sarifToFindings("{bad")).toEqual([]);
    expect(sarifToFindings("{}")).toEqual([]);
  });
  it("araç adından modül çıkarır (checkov→CLOUD, nuclei→C)", () => {
    const mk = (tool: string) =>
      sarifToFindings(
        JSON.stringify({ runs: [{ tool: { driver: { name: tool } }, results: [{ ruleId: "r", message: { text: "x" }, locations: [] }] }] }),
      )[0]?.module;
    expect(mk("checkov")).toBe("CLOUD");
    expect(mk("nuclei")).toBe("C");
    expect(mk("semgrep")).toBe("B");
  });
});

describe("OSV-Scanner JSON → Finding normalizasyonu", () => {
  const osv = JSON.stringify({
    results: [
      {
        source: { path: "requirements.txt", type: "lockfile" },
        packages: [
          {
            package: { name: "django", version: "3.2.0", ecosystem: "PyPI" },
            vulnerabilities: [
              {
                id: "GHSA-xxxx",
                summary: "SQL injection in Django",
                aliases: ["CVE-2022-28346"],
                severity: [{ type: "CVSS_V3", score: "9.8" }],
              },
            ],
          },
        ],
      },
    ],
  });

  const findings = osvToFindings(osv);

  it("çok-ekosistem paket zafiyetini P0 olarak üretir", () => {
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("P0");
    expect(findings[0]?.check).toBe("B2");
  });
  it("CVE + paket adını taşır, autoFixable", () => {
    const f = findings[0]!;
    expect(f.cves).toContain("CVE-2022-28346");
    expect(f.autoFixable).toBe(true);
    expect(f.evidence[0]?.excerpt).toContain("django");
  });
  it("bozuk girdi → []", () => {
    expect(osvToFindings("nope")).toEqual([]);
  });
});

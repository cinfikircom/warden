import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { createFsContext } from "../src/detect/fs.ts";
import { scanSource } from "../src/modules/sast/scanner.ts";
import { SAST_RULES } from "../src/modules/sast/rules.ts";
import { parseAudit, vulnsToFindings } from "../src/modules/sast/dependency.ts";

const FIXTURE = fileURLToPath(new URL("./fixtures/vuln-prisma-docker", import.meta.url));

// scanSource fixtures'ı SKIP_PATH ile dışlar; bu test için fixture'ı doğrudan kök alıyoruz.
const fs = createFsContext(FIXTURE);
const findings = scanSource(fs, SAST_RULES, { maxFiles: 200 });
const checks = new Set(findings.map((f) => f.check));
const ids = findings.map((f) => f.id.split(":")[0]);

describe("SAST kaynak tarayıcı — bilinen açıkları kanıtla yakalar", () => {
  it("B3 zayıf hash (MD5)", () => {
    expect(ids).toContain("B3-weak-hash");
  });
  it("B3 CryptoJS", () => {
    expect(ids).toContain("B3-cryptojs");
  });
  it("B3 Math.random token", () => {
    expect(ids).toContain("B3-insecure-random");
  });
  it("FE JWT localStorage (P1)", () => {
    const f = findings.find((x) => x.id.startsWith("FE-jwt-localstorage"));
    expect(f?.severity).toBe("P1");
    expect(f?.module).toBe("FE");
  });
  it("FE dangerouslySetInnerHTML", () => {
    expect(ids).toContain("FE-dangerous-html");
  });
  it("B6 SQL concat (P0)", () => {
    const f = findings.find((x) => x.id.startsWith("B6-sql-concat"));
    expect(f?.severity).toBe("P0");
  });
  it("B6 eval", () => {
    expect(ids).toContain("B6-eval");
  });
  it("B7 CORS wildcard", () => {
    expect(ids).toContain("B7-cors-wildcard");
  });
  it("B5 IDOR adayı (düşük güven)", () => {
    const f = findings.find((x) => x.id.startsWith("B5-idor-candidate"));
    expect(f?.confidence).toBe("low");
  });
  it("B1 hardcoded token (sk-...)", () => {
    expect(ids).toContain("B1-token-literal");
  });
  it("her bulgu kanıt taşır (file:line) ve OWASP referansı var", () => {
    expect(findings.length).toBeGreaterThan(5);
    for (const f of findings) {
      expect(f.evidence.length).toBeGreaterThan(0);
      expect(f.evidence[0]?.location).toBeTruthy();
    }
    expect(checks.size).toBeGreaterThan(4);
  });
  it("secret kanıtı maskelenir (tam değer sızmaz)", () => {
    const tok = findings.find((x) => x.id.startsWith("B1-token-literal"));
    expect(tok?.evidence[0]?.excerpt).not.toContain("1234567890abcdef1234567890");
  });
});

describe("B2 dependency audit parser", () => {
  it("npm v7 (vulnerabilities) şeklini ayrıştırır", () => {
    const json = JSON.stringify({
      vulnerabilities: {
        lodash: { name: "lodash", severity: "critical", via: [{ title: "Prototype Pollution" }], range: "<4.17.21" },
        axios: { name: "axios", severity: "moderate", via: [{ title: "SSRF" }], range: "<1.6.0" },
      },
    });
    const vulns = parseAudit(json);
    expect(vulns).toHaveLength(2);
    const findings = vulnsToFindings(vulns);
    expect(findings.find((f) => f.id === "B2-vuln:lodash")?.severity).toBe("P0");
    expect(findings.find((f) => f.id === "B2-vuln:axios")?.severity).toBe("P2");
  });

  it("v6/pnpm (advisories) şeklini ayrıştırır", () => {
    const json = JSON.stringify({
      advisories: { "1234": { module_name: "minimist", severity: "high", title: "Prototype Pollution", vulnerable_versions: "<1.2.6" } },
    });
    const findings = vulnsToFindings(parseAudit(json));
    expect(findings.find((f) => f.id === "B2-vuln:minimist")?.severity).toBe("P1");
  });

  it("bozuk JSON → boş", () => {
    expect(parseAudit("{not json")).toHaveLength(0);
  });
});

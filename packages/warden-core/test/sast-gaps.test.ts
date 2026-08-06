import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { createFsContext } from "../src/detect/fs.ts";
import { scanSource } from "../src/modules/sast/scanner.ts";
import { SAST_RULES } from "../src/modules/sast/rules.ts";

const GAPS = fileURLToPath(new URL("./fixtures/vuln-gaps", import.meta.url));

const g = scanSource(createFsContext(GAPS), SAST_RULES, { maxFiles: 100 });
const gIds = new Set(g.map((f) => f.id.split(":")[0]));

describe("v0.10 kapsam boşlukları — NoSQL / LDAP injection (OWASP A03)", () => {
  it("$where JavaScript enjeksiyonu → P0", () => {
    expect(g.find((x) => x.id.startsWith("B6-nosql-where"))?.severity).toBe("P0");
  });
  it("NoSQL operatör enjeksiyonu → P1 / low (heuristik)", () => {
    const f = g.find((x) => x.id.startsWith("B6-nosql-operator"));
    expect(f?.severity).toBe("P1");
    expect(f?.confidence).toBe("low");
  });
  it("LDAP filtre birleştirmesi → P0", () => {
    expect(g.find((x) => x.id.startsWith("B6-ldap-injection"))?.severity).toBe("P0");
  });
});

describe("v0.10 kapsam boşlukları — sabit IV (OWASP A02)", () => {
  it("createCipheriv sabit IV ile", () => {
    expect(gIds.has("B3-static-iv")).toBe(true);
  });
  it("modül düzeyinde sabit IV tanımı", () => {
    expect(gIds.has("B3-static-iv-const")).toBe(true);
  });
  it("Python AES.new sabit IV", () => {
    expect(gIds.has("B3-static-iv-py")).toBe(true);
  });
});

describe("v0.10 kapsam boşlukları — zayıf JWT secret (OWASP A02/A07)", () => {
  it("jwt.sign sözlük secret'ı ile → P0", () => {
    expect(g.find((x) => x.id.startsWith("B4-weak-jwt-secret:"))?.severity).toBe("P0");
  });
  it("yapılandırmada zayıf secret", () => {
    expect(gIds.has("B4-weak-jwt-secret-config")).toBe(true);
  });
});

describe("v0.10 kapsam boşlukları — çıktı sözleşmesi", () => {
  it("yeni bulguların hepsi OWASP A0x:2021 referansı taşır", () => {
    for (const f of g) {
      expect(f.references?.some((r) => /^OWASP A\d{2}:2021$/.test(r))).toBe(true);
    }
  });
  it("her bulgu kanıt taşır (dosya + satır)", () => {
    for (const f of g) {
      expect(f.evidence[0]?.source).toBeTruthy();
      expect(f.evidence[0]?.location).toBeTruthy();
    }
  });
});

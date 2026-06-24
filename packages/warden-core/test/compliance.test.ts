import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { createFsContext } from "../src/detect/fs.ts";
import { collectComplianceData } from "../src/modules/compliance/index.ts";
import { analyzeCompliance } from "../src/modules/compliance/checks.ts";
import type { ComplianceData } from "../src/modules/compliance/checks.ts";
import { checklistScore } from "../src/model/compliance.ts";

const FIXTURE = fileURLToPath(new URL("./fixtures/vuln-prisma-docker", import.meta.url));

const EMPTY: ComplianceData = {
  deps: {}, hasCI: false, ciFiles: [], ciHasTestGate: false,
  prismaSchema: null, hasPersonalData: false, cardHits: [], hasBackup: false, hasRestore: false,
};

describe("Modül D — saf analiz", () => {
  it("observability/secret-mgr/CI yoksa D2/D3/D5 üretir", () => {
    const { findings } = analyzeCompliance(EMPTY);
    const ids = findings.map((f) => f.id);
    expect(ids).toContain("D2-no-error-tracking");
    expect(ids).toContain("D3-no-secret-manager");
    expect(ids).toContain("D5-no-ci");
  });

  it("Sentry + CI(test) varsa D2/D5 üretmez", () => {
    const { findings } = analyzeCompliance({
      ...EMPTY, deps: { "@sentry/node": "^8" }, hasCI: true, ciFiles: [".github/workflows/ci.yml"], ciHasTestGate: true,
    });
    const ids = findings.map((f) => f.id);
    expect(ids).not.toContain("D2-no-error-tracking");
    expect(ids).not.toContain("D5-no-ci");
  });

  it("CVV saklama → P0, PAN → P1 (D7)", () => {
    const { findings } = analyzeCompliance({
      ...EMPTY,
      cardHits: [
        { file: "a.ts", line: 3, kind: "cvv", excerpt: "cvv: string" },
        { file: "a.ts", line: 2, kind: "pan", excerpt: "cardNumber: string" },
      ],
    });
    expect(findings.find((f) => f.id.startsWith("D7-cvv-storage"))?.severity).toBe("P0");
    expect(findings.find((f) => f.id.startsWith("D7-pan-storage"))?.severity).toBe("P1");
  });

  it("PCI checklist: CVV saklanınca req 3.2 fail", () => {
    const { result } = analyzeCompliance({
      ...EMPTY, cardHits: [{ file: "a.ts", line: 3, kind: "cvv", excerpt: "cvv" }],
    });
    const pci = result.checklists.find((c) => c.standard === "PCI-DSS 4.0");
    expect(pci?.items.find((i) => i.control === "PCI 3.2")?.status).toBe("fail");
  });

  it("kişisel veri + soft-delete yoksa D4; privacy checklist üretilir", () => {
    const { findings, result } = analyzeCompliance({
      ...EMPTY, prismaSchema: "model User { id String @id\n email String }", hasPersonalData: true,
    });
    expect(findings.find((f) => f.id === "D4-no-soft-delete")?.severity).toBe("P2");
    expect(result.checklists.some((c) => c.standard === "GDPR/KVKK")).toBe(true);
  });
});

describe("Modül D entegrasyon (fixture)", () => {
  it("fixture: CVV(P0)+PAN(P1) kart verisi yakalanır, checklist'ler üretilir", () => {
    const data = collectComplianceData(createFsContext(FIXTURE));
    const { findings, result } = analyzeCompliance(data);
    expect(findings.find((f) => f.id.startsWith("D7-cvv-storage"))?.severity).toBe("P0");
    expect(findings.find((f) => f.id.startsWith("D7-pan-storage"))?.severity).toBe("P1");
    expect(data.hasPersonalData).toBe(true);
    expect(result.checklists).toHaveLength(2);
    // checklist skoru hesaplanabilir olmalı
    const pci = result.checklists.find((c) => c.standard === "PCI-DSS 4.0")!;
    expect(checklistScore(pci).failed).toBeGreaterThan(0);
  });
});

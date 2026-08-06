import { describe, it, expect } from "vitest";
import { buildOwaspChecklist, owaspCategoriesOf } from "../src/risk/owasp.ts";
import { makeFinding } from "../src/util/finding.ts";
import type { Finding, ModuleId } from "../src/model/finding.ts";
import { DIMENSIONS, buildScoreboard, overallScore } from "../src/report/scoreboard.ts";
import { MODULES } from "../src/model/finding.ts";

function f(id: string, module: ModuleId, check: string, references?: string[], extra: Partial<Finding> = {}): Finding {
  return {
    ...makeFinding({
      id,
      title: id,
      severity: "P1",
      module,
      check,
      category: "x",
      confidence: "high",
      evidence: [{ type: "file", source: "x.ts", location: "1" }],
      impact: "i",
      recommendation: "r",
      effort: "S",
      autoFixable: false,
      ...(references ? { references } : {}),
    }),
    ...extra,
  };
}

const statusOf = (list: ReturnType<typeof buildOwaspChecklist>, control: string): string | undefined =>
  list.items.find((i) => i.control === control)?.status;

describe("OWASP checklist — L1 referans katmanı", () => {
  it("referanstan A03 → fail", () => {
    expect(statusOf(buildOwaspChecklist([f("B6-sql-concat:a:1", "B", "B6", ["OWASP A03:2021"])]), "A03:2021")).toBe("fail");
  });

  it("bulgu yoksa TÜM satırlar unknown — 'pass' ASLA üretilmez (dürüstlük ilkesi)", () => {
    const l = buildOwaspChecklist([]);
    expect(l.items).toHaveLength(10);
    expect(l.items.every((i) => i.status === "unknown")).toBe(true);
    expect(l.items.some((i) => i.status === "pass")).toBe(false);
  });

  it("temiz olduğu bilinen bulgu kümesinde bile 'pass' üretilmez", () => {
    const l = buildOwaspChecklist([f("ZZ-noise", "B", "ZZ0", ["ISO 27001 A.12"])]);
    expect(l.items.some((i) => i.status === "pass")).toBe(false);
  });

  it("references alanı yoksa çökmez (savunmacı erişim)", () => {
    expect(() => buildOwaspChecklist([f("ZZ", "B", "ZZ0")])).not.toThrow();
  });
});

describe("OWASP checklist — TUZAK savunması (anchored regex)", () => {
  it("KEV/EPSS/reachability serbest metinleri hiçbir kategoriyi tetiklemez", () => {
    const noisy = f("ZZ-noise", "B", "ZZ0", [
      "CISA KEV (aktif sömürülüyor)",
      "EPSS 87.3%",
      "reachable (import grafında)",
      "unreachable (import grafında yok — olası transitif)",
    ]);
    expect(owaspCategoriesOf(noisy).size).toBe(0);
    expect(buildOwaspChecklist([noisy]).items.every((i) => i.status === "unknown")).toBe(true);
  });

  it("OWASP API Top 10 kodları (API1/API5:2023) A01'i tetiklemez — farklı taksonomi", () => {
    const api = f("ZZ", "B", "ZZ0", ["OWASP API1 (BOLA)", "OWASP API5:2023", "OWASP API8"]);
    expect(owaspCategoriesOf(api).size).toBe(0);
    expect(statusOf(buildOwaspChecklist([api]), "A01:2021")).toBe("unknown");
  });

  it("OWASP LLM kodları da eşleşmez", () => {
    expect(owaspCategoriesOf(f("ZZ", "AI", "AI-1", ["OWASP LLM01"])).size).toBe(0);
  });

  it("geçerli kod baştan/sondan boşluklu gelse de tanınır", () => {
    expect([...owaspCategoriesOf(f("ZZ", "B", "ZZ0", ["  OWASP A05:2021  "]))]).toEqual(["A05"]);
  });
});

describe("OWASP checklist — L2 türetme katmanı (referans körlüğünü giderir)", () => {
  it("CLOUD-AWS-s3-public → A01 (bulgu OWASP referansı TAŞIMIYOR)", () => {
    const cloud = f("CLOUD-AWS-s3-public:main.tf:3", "CLOUD", "CLOUD-AWS", ["CIS AWS Benchmark"]);
    expect(owaspCategoriesOf(cloud).size).toBe(0); // L1 kör
    expect(statusOf(buildOwaspChecklist([cloud]), "A01:2021")).toBe("fail"); // L2 yakalar
  });

  it("açık güvenlik grubu → A05 (public veri deposu ile aynı kategoriye düşmez)", () => {
    const l = buildOwaspChecklist([f("CLOUD-AWS-sg-open:main.tf:9", "CLOUD", "CLOUD-AWS", ["CIS AWS Benchmark"])]);
    expect(statusOf(l, "A05:2021")).toBe("fail");
    expect(statusOf(l, "A01:2021")).toBe("unknown");
  });

  it("K8S-privileged → A05, K8S-plain-secret → A07", () => {
    const l = buildOwaspChecklist([
      f("K8S-privileged:a/b.yaml", "K8S", "K8S-1", ["CIS Kubernetes Benchmark"]),
      f("K8S-plain-secret:a/b.yaml:PW", "K8S", "K8S-4", ["CIS Kubernetes Benchmark"]),
    ]);
    expect(statusOf(l, "A05:2021")).toBe("fail");
    expect(statusOf(l, "A07:2021")).toBe("fail");
  });

  it("CVE taşıyan SARIF/OSV içe-aktarımı → A06 (check araç kural-id'sidir)", () => {
    const ext = f("EXT-trivy-1", "B", "avd-aws-0089", ["Trivy"], { cves: ["CVE-2024-1234"] });
    expect(statusOf(buildOwaspChecklist([ext]), "A06:2021")).toBe("fail");
  });

  it("B6 ailesi doğru bölünür: SSRF→A10, path traversal→A01, XXE→A05, diğerleri→A03", () => {
    const ssrf = buildOwaspChecklist([f("B6-ssrf-node:a:1", "B", "B6")]);
    expect(statusOf(ssrf, "A10:2021")).toBe("fail");
    expect(statusOf(ssrf, "A03:2021")).toBe("unknown");

    const trav = buildOwaspChecklist([f("B6-path-traversal-node:a:1", "B", "B6")]);
    expect(statusOf(trav, "A01:2021")).toBe("fail");
    expect(statusOf(trav, "A03:2021")).toBe("unknown");

    const xxe = buildOwaspChecklist([f("B6-xxe-py:a:1", "B", "B6")]);
    expect(statusOf(xxe, "A05:2021")).toBe("fail");
    expect(statusOf(xxe, "A03:2021")).toBe("unknown");

    const sql = buildOwaspChecklist([f("B6-sql-concat:a:1", "B", "B6")]);
    expect(statusOf(sql, "A03:2021")).toBe("fail");
  });

  it("FE modülü kontrolleri doğru kategorilere düşer (FE-1→A07, FE-3→A03, FE-2→A05)", () => {
    expect(statusOf(buildOwaspChecklist([f("FE-jwt-localstorage:a:1", "FE", "FE-1")]), "A07:2021")).toBe("fail");
    expect(statusOf(buildOwaspChecklist([f("FE-dangerous-html:a:1", "FE", "FE-3")]), "A03:2021")).toBe("fail");
    expect(statusOf(buildOwaspChecklist([f("FE-csp-unsafe:a:1", "FE", "FE-2")]), "A05:2021")).toBe("fail");
  });

  it("D4 (soft-delete yok) A09'a BAĞLANMAZ — veri koruma konusu, loglama değil", () => {
    expect(statusOf(buildOwaspChecklist([f("D4-no-soft-delete", "D", "D4", ["GDPR Art.17"])]), "A09:2021")).toBe("unknown");
  });

  it("D2 (hata izleme yok) → A09", () => {
    expect(statusOf(buildOwaspChecklist([f("D2-no-error-tracking", "D", "D2", ["D2", "OWASP A09:2021"])]), "A09:2021")).toBe("fail");
  });
});

describe("OWASP checklist — izlenebilirlik", () => {
  it("note tetikleyen kural kimliklerini ve P0 sayısını taşır", () => {
    const l = buildOwaspChecklist([
      f("B6-sql-concat:a:1", "B", "B6", ["OWASP A03:2021"], { severity: "P0" }),
      f("B6-eval:b:2", "B", "B6", ["OWASP A03:2021"]),
    ]);
    const note = l.items.find((i) => i.control === "A03:2021")?.note ?? "";
    expect(note).toContain("B6-sql-concat");
    expect(note).toContain("P0: 1");
  });

  it("checklist adı ve standardı sabittir (rapor başlıkları buna dayanır)", () => {
    const l = buildOwaspChecklist([]);
    expect(l.name).toBe("OWASP Top 10:2021");
    expect(l.standard).toBe("OWASP Top 10");
  });
});

describe("Modül E'nin emekliye ayrılması", () => {
  it("MODULES listesinde 'E' yok", () => {
    expect((MODULES as readonly string[]).includes("E")).toBe(false);
  });

  it("skor tablosunda 'OWASP Top 10 / ASVS' boyutu yok (kalıcı n/d satırı kalktı)", () => {
    expect(Object.keys(DIMENSIONS)).not.toContain("E");
    expect(buildScoreboard([], new Set()).some((r) => (r.module as string) === "E")).toBe(false);
  });

  it("E'nin kaldırılması genel skoru DEĞİŞTİRMEZ (n/d satırları zaten ortalamaya girmiyordu)", () => {
    expect(overallScore(buildScoreboard([], new Set(["B" as const])))).toBe(10);
  });
});

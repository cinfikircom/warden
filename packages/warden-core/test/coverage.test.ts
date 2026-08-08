import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readdirSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CoverageCollector, LIMIT_KINDS } from "../src/report/coverage.ts";
import { scanSource } from "../src/modules/sast/scanner.ts";
import { SAST_RULES } from "../src/modules/sast/rules.ts";
import { createFsContext, DEFAULT_FILE_LIMIT } from "../src/detect/fs.ts";
import { buildScoreboard, overallScore } from "../src/report/scoreboard.ts";
import type { Finding } from "../src/model/finding.ts";
import { makeFinding } from "../src/util/finding.ts";

/**
 * KAPSAM BEYANI testleri.
 *
 * Bu katmanın tek işi dürüstlük: "bakamadım" ile "baktım, temiz"i ayırt edilebilir kılmak.
 * Buradaki testler o ayrımın iki yönünü de korur — kaybı gizlememek KADAR olmayan kaybı
 * bildirmemek de sözleşmenin parçası, çünkü yanlış alarm üreten bir beyan güvenilmez olur.
 */

function tmpTree(): string {
  return mkdtempSync(join(tmpdir(), "warden-cov-"));
}

describe("CoverageCollector — kayıp muhasebesi", () => {
  it("aynı örnek tekrar bildirilirse tek sayılır (find() her modülde yeniden çağrılır)", () => {
    const c = new CoverageCollector();
    for (let i = 0; i < 18; i++) c.limit("depth", "depth", "derin", "apps/web/deep");
    const m = c.build();
    expect(m.limits).toHaveLength(1);
    expect(m.limits[0]?.count).toBe(1);
  });

  it("farklı örnekler ayrı sayılır ve örnek listesi 5 ile sınırlanır", () => {
    const c = new CoverageCollector();
    for (let i = 0; i < 12; i++) c.limit("depth", "depth", "derin", `dir-${i}`);
    const m = c.build();
    expect(m.limits[0]?.count).toBe(12);
    expect(m.limits[0]?.samples).toHaveLength(5);
  });

  it("örneksiz kayıplar her çağrıda sayılır", () => {
    const c = new CoverageCollector();
    c.limit("fc", "file-count", "tavan");
    c.limit("fc", "file-count", "tavan");
    expect(c.build().limits[0]?.count).toBe(2);
  });

  it("dosya kapsamı yüzdesi taranan ve atlanandan hesaplanır", () => {
    const c = new CoverageCollector();
    for (let i = 0; i < 9; i++) c.fileScanned(`src/f${i}.ts`);
    c.limit("size", "file-size", "büyük", "src/big.ts");
    const m = c.build();
    expect(m.filesScanned).toBe(9);
    expect(m.filesSkipped).toBe(1);
    expect(m.fileCoveragePercent).toBe(90);
  });

  it("hiç dosya taranmadıysa yüzde uydurulmaz (null)", () => {
    expect(new CoverageCollector().build().fileCoveragePercent).toBeNull();
  });

  it("aynı dosya iki modül tarafından okunsa da bir kez sayılır", () => {
    const c = new CoverageCollector();
    c.fileScanned("src/a.ts");
    c.fileScanned("src/a.ts");
    expect(c.build().filesScanned).toBe(1);
  });
});

/**
 * ÖLÜ SAYAÇ KORUMASI.
 *
 * Bu, bu dosyadaki en önemli test. Tanımlı ama hiç doldurulmayan bir kapsam sayacı, olmayan
 * bir güvenceyi varmış gibi gösterir — ve normal testler onu yakalayamaz, çünkü "her zaman
 * sıfır" geçerli bir sonuç gibi görünür. KICS'in `files_failed_to_scan` alanı tam olarak
 * böyle öldü; Warden'ın ilk uygulamasında da üç tür bağlanmadan kalmıştı.
 */
describe("LimitKind — tanımlı her tür gerçekten üretiliyor mu", () => {
  const srcDir = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

  function allSource(dir: string, out: string[] = []): string[] {
    for (const e of readdirSync(dir)) {
      const p = join(dir, e);
      if (statSync(p).isDirectory()) allSource(p, out);
      else if (p.endsWith(".ts") && !p.endsWith("report/coverage.ts")) out.push(readFileSync(p, "utf8"));
    }
    return out;
  }

  const sources = allSource(srcDir).join("\n");

  it.each(LIMIT_KINDS)("'%s' türü için en az bir üretim çağrısı var", (kind) => {
    // `coverage.limit(key, kind, ...)` çağrısında tür ikinci argümandır.
    expect(sources, `LimitKind "${kind}" tanımlı ama hiçbir yerde üretilmiyor — ölü sayaç.`)
      .toContain(`"${kind}"`);
  });
});

describe("no-rules-for-language — 'tarandı' ile 'denetlendi' ayrımı", () => {
  it("Ruby dosyası okunur ama dile özgü kural olmadığı için kayıp bildirilir", () => {
    const root = tmpTree();
    try {
      mkdirSync(join(root, "app"), { recursive: true });
      writeFileSync(join(root, "app", "user.rb"), "class User\n  def name\n    @name\n  end\nend\n");
      const cov = new CoverageCollector();
      const fs = createFsContext(root, { coverage: cov });
      scanSource(fs, SAST_RULES, { coverage: cov });

      const hit = cov.build().limits.find((l) => l.kind === "no-rules-for-language");
      expect(hit, "Ruby için kural yokluğu bildirilmedi").toBeDefined();
      expect(hit?.detail).toContain(".rb");
      // Dosya yine de "tarandı" sayılır — okundu, sadece derinlemesine denetlenmedi.
      expect(cov.build().filesScanned).toBe(1);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("TypeScript dosyasında dile özgü kural VAR, kayıp bildirilmez", () => {
    const root = tmpTree();
    try {
      mkdirSync(join(root, "src"), { recursive: true });
      writeFileSync(join(root, "src", "a.ts"), "export const x = 1;\n");
      const cov = new CoverageCollector();
      const fs = createFsContext(root, { coverage: cov });
      scanSource(fs, SAST_RULES, { coverage: cov });

      expect(cov.build().limits.find((l) => l.kind === "no-rules-for-language")).toBeUndefined();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("file-size — büyük dosya sessizce atlanmaz", () => {
  it("boyut tavanını aşan dosya kayıp olarak bildirilir", () => {
    const root = tmpTree();
    try {
      mkdirSync(join(root, "src"), { recursive: true });
      writeFileSync(join(root, "src", "huge.ts"), "// ".repeat(5000));
      const cov = new CoverageCollector();
      const fs = createFsContext(root, { coverage: cov });
      scanSource(fs, SAST_RULES, { coverage: cov, maxBytesPerFile: 100 });

      const hit = cov.build().limits.find((l) => l.kind === "file-size");
      expect(hit).toBeDefined();
      expect(hit?.samples[0]).toContain("huge.ts");
      expect(cov.build().filesScanned).toBe(0); // okunmadı sayılır
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("createFsContext — derinlik ve tavan kesmeleri raporlanır", () => {
  it("derinlik sınırında kesilen dizin kaydedilir", () => {
    const root = tmpTree();
    try {
      const deep = join(root, "a", "b", "c", "d", "e", "f", "g");
      mkdirSync(deep, { recursive: true });
      writeFileSync(join(deep, "gizli.ts"), "export const x = 1;");
      const cov = new CoverageCollector();
      const fs = createFsContext(root, { coverage: cov, maxDepth: 3 });
      const found = fs.find((p) => p.endsWith(".ts"));

      expect(found).toHaveLength(0); // dosya derinlikte kaldı
      const hit = cov.build().limits.find((l) => l.kind === "depth");
      expect(hit).toBeDefined();
      expect(hit?.samples.length).toBeGreaterThan(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("--max-depth verilince daha derin dosyalar görünür ve kayıp raporlanmaz", () => {
    const root = tmpTree();
    try {
      const deep = join(root, "a", "b", "c", "d", "e", "f", "g");
      mkdirSync(deep, { recursive: true });
      writeFileSync(join(deep, "gizli.ts"), "export const x = 1;");
      const cov = new CoverageCollector();
      const fs = createFsContext(root, { coverage: cov, maxDepth: 12 });

      expect(fs.find((p) => p.endsWith(".ts"))).toHaveLength(1);
      expect(cov.build().limits.find((l) => l.kind === "depth")).toBeUndefined();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  /**
   * Regresyon koruması: modüllerin çoğu "bu projede X var mı?" diye sorarken {limit:1}
   * geçer. İlk uygulamada bu, her seferinde "dosya tavanına ulaşıldı" kaybı üretiyordu —
   * yani beyanın kendisi yanlış alarm fabrikasına dönmüştü.
   */
  it("çağıranın kasıtlı küçük limiti ({limit:1} sondajı) kayıp SAYILMAZ", () => {
    const root = tmpTree();
    try {
      mkdirSync(join(root, "src"), { recursive: true });
      for (const n of ["a", "b", "c"]) writeFileSync(join(root, "src", `${n}.ts`), "x");
      const cov = new CoverageCollector();
      const fs = createFsContext(root, { coverage: cov });

      expect(fs.find((p) => p.endsWith(".ts"), { limit: 1 })).toHaveLength(1);
      expect(cov.build().limits.find((l) => l.kind === "file-count")).toBeUndefined();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("kullanıcının --max-files tavanına ulaşmak GERÇEK kayıptır ve raporlanır", () => {
    const root = tmpTree();
    try {
      mkdirSync(join(root, "src"), { recursive: true });
      for (const n of ["a", "b", "c"]) writeFileSync(join(root, "src", `${n}.ts`), "x");
      const cov = new CoverageCollector();
      const fs = createFsContext(root, { coverage: cov, maxFiles: 2 });

      expect(fs.find((p) => p.endsWith(".ts"))).toHaveLength(2);
      expect(cov.build().limits.find((l) => l.kind === "file-count")).toBeDefined();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("test/fixture ağaçlarındaki derinlik kesmesi kayıp sayılmaz (kural katmanı zaten eliyor)", () => {
    const root = tmpTree();
    try {
      const deep = join(root, "test", "fixtures", "a", "b", "c", "d", "e");
      mkdirSync(deep, { recursive: true });
      writeFileSync(join(deep, "x.ts"), "x");
      const cov = new CoverageCollector();
      createFsContext(root, { coverage: cov, maxDepth: 2 }).find(() => true);

      expect(cov.build().limits.find((l) => l.kind === "depth")).toBeUndefined();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("varsayılan tavan sabiti beklenen değerde (sondaj eşiği buna bağlı)", () => {
    expect(DEFAULT_FILE_LIMIT).toBe(2000);
  });
});

function dummyFinding(module: Finding["module"]): Finding {
  return makeFinding({
    id: `${module}-x`,
    title: "test bulgusu",
    severity: "P2",
    module,
    check: "X1",
    category: "Test",
    confidence: "medium",
    evidence: [{ type: "file", source: "a.ts", excerpt: "x" }],
    impact: "-",
    recommendation: "-",
    effort: "S",
    autoFixable: false,
  });
}

describe("buildScoreboard — 'kapsam dışı' ayrımı", () => {
  const manifest = (status: "surface-absent" | "failed" | "audited", surface: number | null) => ({
    filesScanned: 1,
    filesSkipped: 0,
    fileCoveragePercent: 100,
    limits: [],
    unmeasured: [],
    modules: [
      { module: "PAY" as const, title: "Ödeme", status, reason: status === "failed" ? "çöktü" : "yüzey yok", surface, findings: 0 },
    ],
  });

  it("yüzey bulamayan modül 10.0 DEĞİL 'kapsam dışı' alır ve ortalamaya girmez", () => {
    const rows = buildScoreboard([], new Set(["PAY"]), manifest("surface-absent", 0));
    const pay = rows.find((r) => r.module === "PAY");
    expect(pay?.score).toBeNull();
    expect(pay?.status).toBe("surface-absent");
    expect(overallScore(rows)).toBeNull(); // puanlı tek boyut kalmadı
  });

  it("çöken modül puan almaz — denetlenmemiş boyut temiz görünemez", () => {
    const rows = buildScoreboard([], new Set(["PAY"]), manifest("failed", null));
    const pay = rows.find((r) => r.module === "PAY");
    expect(pay?.score).toBeNull();
    expect(pay?.status).toBe("failed");
    expect(pay?.note).toBe("çöktü");
  });

  /**
   * Bulgu, yüzeyin var olduğunun kesin kanıtıdır — SARIF içe-aktarımı gibi başka bir
   * kaynaktan gelmiş olabilir. O yüzden "kapsam dışı" kuralı bulgu varken UYGULANMAZ.
   */
  it("bulgu varsa 'kapsam dışı' kuralı uygulanmaz, boyut puanlanır", () => {
    const rows = buildScoreboard([dummyFinding("PAY")], new Set(["PAY"]), manifest("surface-absent", 0));
    const pay = rows.find((r) => r.module === "PAY");
    expect(pay?.score).toBe(9);
    expect(pay?.status).toBe("audited");
  });

  it("yüzey bulan modül eskisi gibi puanlanır", () => {
    const rows = buildScoreboard([], new Set(["PAY"]), manifest("audited", 4));
    expect(rows.find((r) => r.module === "PAY")?.score).toBe(10);
  });

  it("kapsam bilgisi verilmezse davranış eskisiyle aynı kalır (geriye dönük uyum)", () => {
    const rows = buildScoreboard([], new Set(["PAY"]));
    expect(rows.find((r) => r.module === "PAY")?.score).toBe(10);
  });
});

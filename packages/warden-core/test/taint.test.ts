import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { buildTaintMap, evaluateTaint, adjustConfidence } from "../src/modules/sast/taint.ts";
import { scanSource } from "../src/modules/sast/scanner.ts";
import type { SourceRule } from "../src/modules/sast/scanner.ts";
import { createFsContext } from "../src/detect/fs.ts";

const FIXTURE = fileURLToPath(new URL("./fixtures/vuln-taint", import.meta.url));

const L = (s: string): string[] => s.split("\n");

describe("buildTaintMap — kaynak yayılımı", () => {
  it("doğrudan atamayla taint yayılır", () => {
    const m = buildTaintMap(L(`const ad = req.body.name;`));
    expect(m.vars.has("ad")).toBe(true);
    expect(m.vars.get("ad")?.sourceExpr).toContain("req.body");
  });

  it("zincirleme atamayla taint yayılır", () => {
    const m = buildTaintMap(L([`const a = req.query.q;`, `const b = a + "x";`, `const c = b;`].join("\n")));
    expect(m.vars.has("c")).toBe(true);
  });

  it("destructuring ile taint yayılır", () => {
    const m = buildTaintMap(L(`const { cmd, other } = req.body;`));
    expect(m.vars.has("cmd")).toBe(true);
    expect(m.vars.has("other")).toBe(true);
  });

  it("kelime sınırına saygı duyar: `id` taint'i `idx`'e sızmaz", () => {
    const m = buildTaintMap(L([`const id = req.params.id;`, `const idx = 5;`].join("\n")));
    expect(m.vars.has("id")).toBe(true);
    expect(m.vars.has("idx")).toBe(false);
  });

  it("yorum satırlarındaki kaynak ifadeleri sayılmaz", () => {
    const m = buildTaintMap(L([`// const a = req.body.x;`, `const b = "sabit";`].join("\n")));
    expect(m.vars.has("a")).toBe(false);
    expect(m.vars.has("b")).toBe(false);
  });

  it("temizleyici taint'i keser", () => {
    const m = buildTaintMap(L(`const id = parseInt(req.query.id, 10);`));
    expect(m.vars.has("id")).toBe(false);
  });

  it("yeniden atamayla temizlenen değişken taint'ten düşer", () => {
    const m = buildTaintMap(L([`let x = req.body.html;`, `x = DOMPurify.sanitize(x);`].join("\n")));
    expect(m.vars.has("x")).toBe(false);
  });

  it("tarayıcı tarafı kaynaklar da tanınır", () => {
    for (const src of [`const a = location.hash;`, `const a = new URLSearchParams(y);`, `const a = document.referrer;`]) {
      expect(buildTaintMap(L(src)).vars.has("a"), src).toBe(true);
    }
  });
});

describe("evaluateTaint — sink değerlendirmesi", () => {
  it("aynı satırda doğrudan kaynak kullanımı yakalanır", () => {
    const m = buildTaintMap(L(`cp.exec(req.body.cmd);`));
    const t = evaluateTaint(m, `cp.exec(req.body.cmd);`, 1);
    expect(t?.reached).toBe(true);
  });

  it("tainted değişken sink'te kullanılınca yakalanır", () => {
    const src = [`const cmd = req.body.cmd;`, `cp.exec("ls " + cmd);`];
    const m = buildTaintMap(L(src.join("\n")));
    expect(evaluateTaint(m, src[1] as string, 2)?.reached).toBe(true);
  });

  it("ilgisiz sink'te taint bulunmaz", () => {
    const src = [`const cmd = req.body.cmd;`, `cp.exec("ls -la");`];
    const m = buildTaintMap(L(src.join("\n")));
    expect(evaluateTaint(m, src[1] as string, 2)).toBeNull();
  });
});

describe("adjustConfidence — ASİMETRİK sinyal", () => {
  /**
   * Bu davranış bu katmanın en önemli güvencesi: motor dosya-içi ve sınırlı olduğu için
   * "ulaşmıyor" kararı güvenilir değildir. Taint bulunamadığında güveni düşürmek,
   * fonksiyonlar arası akışla gelen gerçek bir zafiyeti sessizce gölgelerdi.
   */
  it("taint bulunamazsa güven DEĞİŞMEZ", () => {
    expect(adjustConfidence("high", null)).toBe("high");
    expect(adjustConfidence("medium", null)).toBe("medium");
    expect(adjustConfidence("low", null)).toBe("low");
  });

  it("girdi ulaşıyorsa güven yükselir", () => {
    const t = { reached: true, sourceLine: 1, sourceExpr: "req.body", sanitized: false };
    expect(adjustConfidence("low", t)).toBe("medium");
    expect(adjustConfidence("medium", t)).toBe("high");
    expect(adjustConfidence("high", t)).toBe("high");
  });

  it("temizlenmişse bir kademe düşer ama low'un altına inmez", () => {
    const t = { reached: true, sourceLine: 1, sourceExpr: "req.body", sanitized: true };
    expect(adjustConfidence("high", t)).toBe("medium");
    expect(adjustConfidence("medium", t)).toBe("low");
    expect(adjustConfidence("low", t)).toBe("low");
  });
});

describe("scanSource entegrasyonu (fixture)", () => {
  const sqlRule: SourceRule = {
    id: "T-sql", check: "B6", module: "B", title: "SQL birleştirme",
    severity: "P0", category: "injection", confidence: "medium", taintAware: true,
    pattern: /SELECT[^"']*["']\s*\+|\+\s*["'][^"']*['"]/,
    impact: "i", recommendation: "r", effort: "M",
  };

  it("kullanıcı girdisi ulaşan sink → high + taint kanıtı", () => {
    const ctx = createFsContext(FIXTURE);
    const found = scanSource(ctx, [sqlRule], { include: /\.js$/, skip: /node_modules/ });
    const tainted = found.filter((f) => f.taint?.reached === true);
    expect(tainted.length).toBeGreaterThan(0);
    expect(tainted.every((f) => f.confidence === "high")).toBe(true);
    expect(tainted[0]?.taint?.sourceExpr).toContain("req.");
  });

  it("taint bilgisi fingerprint'i DEĞİŞTİRMEZ (waiver/delta kararlılığı)", () => {
    const ctx = createFsContext(FIXTURE);
    const taintli = scanSource(ctx, [sqlRule], { include: /\.js$/, skip: /node_modules/ });
    const taintsiz = scanSource(ctx, [{ ...sqlRule, taintAware: false }], {
      include: /\.js$/,
      skip: /node_modules/,
    });
    expect(taintli.map((f) => f.fingerprint).sort()).toEqual(taintsiz.map((f) => f.fingerprint).sort());
  });

  it("taint-farkındalı olmayan kural taint alanı taşımaz", () => {
    const ctx = createFsContext(FIXTURE);
    const found = scanSource(ctx, [{ ...sqlRule, taintAware: false }], {
      include: /\.js$/,
      skip: /node_modules/,
    });
    expect(found.every((f) => f.taint === undefined)).toBe(true);
    expect(found.every((f) => f.confidence === "medium")).toBe(true);
  });
});

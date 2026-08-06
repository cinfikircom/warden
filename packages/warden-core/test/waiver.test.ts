import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadWaivers, partitionWaived, WAIVER_FILE } from "../src/risk/waiver.ts";
import { makeFinding } from "../src/util/finding.ts";
import type { Finding } from "../src/model/finding.ts";

/** Test bulgusu: id/check üzerinden eşleşme test edilir; fingerprint makeFinding'den gelir. */
function f(id: string, check: string): Finding {
  return makeFinding({
    id, title: id, severity: "P0", module: "B", check, category: "x", confidence: "high",
    evidence: [{ type: "file", source: "x.ts", location: "1" }],
    impact: "i", recommendation: "r", effort: "S", autoFixable: false,
  });
}

/** Geçici proje kökü + `.warden-ignore.yml` ile loadWaivers'ı izole test eder. */
function withWaiverFile(yaml: string, fn: (root: string) => void): void {
  const root = mkdtempSync(join(tmpdir(), "warden-waiver-"));
  try {
    writeFileSync(join(root, WAIVER_FILE), yaml, "utf8");
    fn(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe("loadWaivers — dosya okuma + doğrulama", () => {
  it("dosya yoksa boş + fileFound=false (güvenli)", () => {
    const root = mkdtempSync(join(tmpdir(), "warden-waiver-empty-"));
    try {
      const r = loadWaivers(root);
      expect(r.fileFound).toBe(false);
      expect(r.waivers).toHaveLength(0);
      expect(r.warnings).toHaveLength(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("geçerli girdileri okur (fingerprint + check + expires)", () => {
    withWaiverFile(
      `waivers:\n  - fingerprint: "abc123"\n    reason: "FP gerekçe"\n  - check: "D7"\n    reason: "D7 gerekçe"\n    expires: "2099-12-31"\n`,
      (root) => {
        const r = loadWaivers(root);
        expect(r.fileFound).toBe(true);
        expect(r.warnings).toHaveLength(0);
        expect(r.waivers).toHaveLength(2);
        expect(r.waivers[0]).toMatchObject({ fingerprint: "abc123", reason: "FP gerekçe" });
        expect(r.waivers[1]).toMatchObject({ check: "D7", expires: "2099-12-31" });
      },
    );
  });

  it("reason'sız ve selector'sız girdileri uyarıyla atlar", () => {
    withWaiverFile(
      `waivers:\n  - fingerprint: "x"\n  - reason: "selector yok"\n  - check: "B3"\n    reason: "geçerli"\n`,
      (root) => {
        const r = loadWaivers(root);
        expect(r.waivers).toHaveLength(1);
        expect(r.waivers[0]?.check).toBe("B3");
        expect(r.warnings).toHaveLength(2);
      },
    );
  });

  it("bozuk YAML'da güvenli boş set + uyarı (PASİF benzeri)", () => {
    withWaiverFile(`waivers:\n  - : : :\n    [bozuk\n`, (root) => {
      const r = loadWaivers(root);
      expect(r.fileFound).toBe(true);
      expect(r.waivers).toHaveLength(0);
      expect(r.warnings.length).toBeGreaterThan(0);
    });
  });

  it("waivers anahtarı yoksa boş set (uyarısız)", () => {
    withWaiverFile(`baska_alan: 1\n`, (root) => {
      const r = loadWaivers(root);
      expect(r.waivers).toHaveLength(0);
      expect(r.warnings).toHaveLength(0);
    });
  });
});

describe("partitionWaived — eşleşme + süre", () => {
  const now = "2026-06-25T00:00:00.000Z";

  it("fingerprint ile tam eşleşmeyi bastırır", () => {
    const a = f("B3-weak-hash:x:1", "B3");
    const b = f("B6-sql:y:2", "B6");
    const { active, waived } = partitionWaived([a, b], [{ fingerprint: a.fingerprint, reason: "r" }], now);
    expect(waived).toHaveLength(1);
    expect(waived[0]?.finding.id).toBe(a.id);
    expect(active.map((x) => x.id)).toEqual([b.id]);
  });

  it("check ile birden çok bulguyu bastırır", () => {
    const d1 = f("D7-cvv:a:1", "D7");
    const d2 = f("D7-cvv:b:2", "D7");
    const other = f("B2-vuln:vite", "B2");
    const { active, waived } = partitionWaived([d1, d2, other], [{ check: "D7", reason: "kendi kuralı" }], now);
    expect(waived).toHaveLength(2);
    expect(active.map((x) => x.id)).toEqual([other.id]);
  });

  it("selector'lar AND ile değerlendirilir (check tutar, id tutmaz → eşleşmez)", () => {
    const d1 = f("D7-cvv:a:1", "D7");
    const { active, waived } = partitionWaived([d1], [{ check: "D7", id: "baska-id", reason: "r" }], now);
    expect(waived).toHaveLength(0);
    expect(active).toHaveLength(1);
  });

  it("süresi geçmiş waiver yok sayılır (bulgu aktif kalır)", () => {
    const d1 = f("D7-cvv:a:1", "D7");
    const { active, waived } = partitionWaived([d1], [{ check: "D7", reason: "r", expires: "2020-01-01" }], now);
    expect(waived).toHaveLength(0);
    expect(active).toHaveLength(1);
  });

  it("expires bugüne eşitse hâlâ geçerli (sınır dahil)", () => {
    const d1 = f("D7-cvv:a:1", "D7");
    const { waived } = partitionWaived([d1], [{ check: "D7", reason: "r", expires: "2026-06-25" }], now);
    expect(waived).toHaveLength(1);
  });

  it("eşleşen waiver'ın gerekçesi bulguya taşınır", () => {
    const d1 = f("D7-cvv:a:1", "D7");
    const { waived } = partitionWaived([d1], [{ check: "D7", reason: "self-match" }], now);
    expect(waived[0]?.reason).toBe("self-match");
  });
});

describe("v0.10 göç uyarısı — E3/E8/E10 check kodları B6/B8 oldu", () => {
  it("eski kodlu waiver yüklenir AMA açık uyarı verilir (sessizce eşleşmez kalmaz)", () => {
    withWaiverFile(
      `waivers:\n  - check: "E10"\n    reason: "eski kod"\n  - check: "E8"\n    reason: "eski kod"\n`,
      (root) => {
        const r = loadWaivers(root);
        expect(r.waivers).toHaveLength(2); // yüklenir — sessizce atılmaz
        expect(r.warnings).toHaveLength(2);
        expect(r.warnings.join(" ")).toContain("B6");
        expect(r.warnings.join(" ")).toContain("B8");
      },
    );
  });

  it("güncel kodlu waiver uyarı üretmez", () => {
    withWaiverFile(`waivers:\n  - check: "B6"\n    reason: "güncel"\n`, (root) => {
      expect(loadWaivers(root).warnings).toHaveLength(0);
    });
  });
});

describe("path selector — yol glob'u ile waiver", () => {
  const now = "2026-06-25T00:00:00.000Z";

  /** Belirtilen kanıt konumlarını taşıyan test bulgusu. */
  function fp(check: string, ...sources: string[]): Finding {
    return makeFinding({
      id: `${check}-x`, title: "t", severity: "P1", module: "B", check, category: "x", confidence: "high",
      evidence: sources.map((s) => ({ type: "file" as const, source: s, location: "1" })),
      impact: "i", recommendation: "r", effort: "S", autoFixable: false,
    });
  }

  it("`**` segment sınırını aşar, `*` aşmaz", () => {
    const derin = fp("B6", "packages/core/src/modules/sast/rules.ts");
    expect(partitionWaived([derin], [{ path: "packages/**", check: "B6", reason: "r" }], now).waived).toHaveLength(1);
    // tek `*` yalnızca bir segment: packages/<tek-segment> ile bitmeli
    expect(partitionWaived([derin], [{ path: "packages/*", check: "B6", reason: "r" }], now).waived).toHaveLength(0);
  });

  it("`**/` sıfır segmentle de eşleşir", () => {
    const kok = fp("B6", "rules.ts");
    const ic = fp("B6", "a/b/rules.ts");
    const w = [{ path: "**/rules.ts", check: "B6", reason: "r" }];
    expect(partitionWaived([kok], w, now).waived).toHaveLength(1);
    expect(partitionWaived([ic], w, now).waived).toHaveLength(1);
  });

  it("bulgu ANCAK tüm kanıtları glob'a uyuyorsa waive edilir", () => {
    const tamamenIcerde = fp("B6", "src/legacy/a.ts", "src/legacy/b.ts");
    const kismen = fp("B6", "src/legacy/a.ts", "src/core/b.ts");
    const w = [{ path: "src/legacy/**", check: "B6", reason: "r" }];
    expect(partitionWaived([tamamenIcerde], w, now).waived).toHaveLength(1);
    expect(partitionWaived([kismen], w, now).waived).toHaveLength(0); // gerçek bulgu yutulmaz
  });

  it("kanıtsız bulgu path waiver'ıyla eşleşmez", () => {
    const kanitsiz = makeFinding({
      id: "D2-x", title: "t", severity: "P2", module: "D", check: "D2", category: "x", confidence: "low",
      evidence: [], impact: "i", recommendation: "r", effort: "S", autoFixable: false,
    });
    expect(partitionWaived([kanitsiz], [{ path: "src/**", reason: "r" }], now).waived).toHaveLength(0);
  });

  it("selector'lar AND ile birleşir: path tutsa da check tutmazsa waive edilmez", () => {
    const b6 = fp("B6", "src/legacy/a.ts");
    expect(partitionWaived([b6], [{ path: "src/legacy/**", check: "B3", reason: "r" }], now).waived).toHaveLength(0);
  });

  it("regex metakarakterleri literal işlenir (glob bir regex enjeksiyon yüzeyi değil)", () => {
    const nokta = fp("B6", "src/a.b.ts");
    // "." glob'da literal nokta demek; regex'teki "herhangi karakter" DEĞİL
    expect(partitionWaived([nokta], [{ path: "src/a.b.ts", check: "B6", reason: "r" }], now).waived).toHaveLength(1);
    expect(partitionWaived([nokta], [{ path: "src/aXb.ts", check: "B6", reason: "r" }], now).waived).toHaveLength(0);
  });

  it("path tek başına geçerli bir selector'dır (fingerprint/check/id şart değil)", () => {
    withWaiverFile(`waivers:\n  - path: "src/legacy/**"\n    reason: "devralınan"\n`, (root) => {
      const r = loadWaivers(root);
      expect(r.waivers).toHaveLength(1);
      expect(r.warnings).toHaveLength(0);
    });
  });

  it("her şeyi kapsayan çıplak glob REDDEDİLİR (sessiz yutma koruması)", () => {
    withWaiverFile(`waivers:\n  - path: "**"\n    reason: "hepsi"\n`, (root) => {
      const r = loadWaivers(root);
      expect(r.waivers).toHaveLength(0);
      expect(r.warnings.join(" ")).toContain("tüm bulguları kapsar");
    });
  });

  it("her şeyi kapsayan glob, başka selector'la daraltılırsa KABUL edilir", () => {
    withWaiverFile(`waivers:\n  - path: "**"\n    check: "B3"\n    reason: "daraltıldı"\n`, (root) => {
      expect(loadWaivers(root).waivers).toHaveLength(1);
    });
  });

  it("aşırı uzun glob reddedilir", () => {
    withWaiverFile(`waivers:\n  - path: "${"a/".repeat(150)}"\n    reason: "uzun"\n`, (root) => {
      const r = loadWaivers(root);
      expect(r.waivers).toHaveLength(0);
      expect(r.warnings.join(" ")).toContain("karakteri aşıyor");
    });
  });

  it("hiçbir selector yoksa uyarı metni path'i de anar", () => {
    withWaiverFile(`waivers:\n  - reason: "selector yok"\n`, (root) => {
      expect(loadWaivers(root).warnings.join(" ")).toContain("path");
    });
  });
});

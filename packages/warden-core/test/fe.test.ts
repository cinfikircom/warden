import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { createFsContext } from "../src/detect/fs.ts";
import { scanSource, CODE_FILE, SKIP_PATH } from "../src/modules/sast/scanner.ts";
import { SAST_RULES } from "../src/modules/sast/rules.ts";
import { FE_RULES } from "../src/modules/fe/rules.ts";
import { hasFrontendSurface, collectFeData, analyzeFe, feModule } from "../src/modules/fe/index.ts";
import type { Finding } from "../src/model/finding.ts";

const fix = (n: string): string => fileURLToPath(new URL(`./fixtures/${n}`, import.meta.url));

// Modülün run()'ı ile aynı tarama parametreleri; scanSource fixtures'ı SKIP_PATH ile dışladığı
// için fixture dizinini doğrudan kök alıyoruz (mevcut sast.test.ts konvansiyonu).
const FE_SCAN_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|mts|cts|vue|svelte|astro|html|htm|njk|ejs|hbs|mdx)$/i;

function scan(dir: string): Finding[] {
  const fs = createFsContext(fix(dir));
  const line = scanSource(fs, FE_RULES, { maxFiles: 200, include: FE_SCAN_FILE, maxDepth: 6 });
  const window = analyzeFe(collectFeData(fs));
  return [...line, ...window];
}

const vuln = scan("vuln-fe");
const vulnIds = new Set(vuln.map((f) => f.id.split(":")[0]));

describe("Modül FE — yüzey tespiti", () => {
  it("react/vue/svelte bağımlılığı olan proje → uygulanabilir", () => {
    expect(hasFrontendSurface(createFsContext(fix("vuln-fe")))).toBe(true);
  });
  it("saf backend projesi → uygulanamaz (FE boyutu doğru şekilde n/d kalır)", () => {
    expect(hasFrontendSurface(createFsContext(fix("safe-app")))).toBe(false);
  });
  it("yüzey yoksa analyzeFe boş döner", () => {
    expect(analyzeFe(collectFeData(createFsContext(fix("safe-app"))))).toEqual([]);
  });
});

describe("Modül FE — FE-3 DOM-XSS sink'leri", () => {
  it("dangerouslySetInnerHTML (React)", () => {
    expect(vulnIds.has("FE-dangerous-html")).toBe(true);
  });
  it("Vue v-html", () => {
    expect(vulnIds.has("FE-vue-vhtml")).toBe(true);
  });
  it("Svelte {@html}", () => {
    expect(vulnIds.has("FE-svelte-html")).toBe(true);
  });
  it("Astro set:html", () => {
    expect(vulnIds.has("FE-astro-set-html")).toBe(true);
  });
  it("innerHTML / document.write", () => {
    expect(vulnIds.has("FE-innerhtml-sink")).toBe(true);
  });
  it("javascript: URL — .html artık taranıyor (eski ÖLÜ kural canlandı)", () => {
    const f = vuln.find((x) => x.id.startsWith("FE-javascript-url"));
    expect(f?.evidence[0]?.source).toBe("public/index.html");
  });
  it("doğrulanmamış dinamik URL binding → P2 / low (heuristik)", () => {
    const f = vuln.find((x) => x.id.startsWith("FE-unsafe-url-binding"));
    expect(f?.severity).toBe("P2");
    expect(f?.confidence).toBe("low");
  });
});

describe("Modül FE — FE-1/2/4/5/6/7", () => {
  it("FE-1 token localStorage'da → check 'FE-1' (eski 'B4' uyuşmazlığı regresyonu)", () => {
    const f = vuln.find((x) => x.id.startsWith("FE-jwt-localstorage"));
    expect(f?.severity).toBe("P1");
    expect(f?.module).toBe("FE");
    expect(f?.check).toBe("FE-1");
  });

  it("FE-2 ÇOK SATIRLI helmet CSP unsafe-inline yakalanır (eski kuralın kaçırdığı hata)", () => {
    const f = vuln.find((x) => x.id.startsWith("FE-csp-unsafe"));
    expect(f).toBeDefined();
    expect(f?.evidence[0]?.source).toBe("server/csp.ts");
  });

  it("FE-2 dosya başına tek bulgu üretir (aynı directives bloğu çoklu anchor içerir)", () => {
    expect(vuln.filter((x) => x.id.startsWith("FE-csp-unsafe"))).toHaveLength(1);
  });

  it("FE-4 next.config.mjs source map (.mjs pathInclude düzeltmesi)", () => {
    const f = vuln.find((x) => x.id.startsWith("FE-source-map-prod"));
    expect(f?.evidence[0]?.source).toBe("next.config.mjs");
  });

  it("FE-5 postMessage wildcard origin → P1 / high", () => {
    const f = vuln.find((x) => x.id.startsWith("FE-postmessage-wildcard"));
    expect(f?.severity).toBe("P1");
    expect(f?.confidence).toBe("high");
  });

  it("FE-5 message dinleyicisinde origin kontrolü yok → yokluk temelli, low", () => {
    const f = vuln.find((x) => x.id.startsWith("FE-message-no-origin"));
    expect(f?.confidence).toBe("low");
    expect(f?.check).toBe("FE-5");
  });

  it("FE-6 target=_blank + rel yok → P3 (modern tarayıcı örtük noopener uygular)", () => {
    const f = vuln.find((x) => x.id.startsWith("FE-tabnabbing"));
    expect(f?.severity).toBe("P3");
  });

  it("FE-7 harici script/stylesheet SRI'sız", () => {
    const sri = vuln.filter((x) => x.id.startsWith("FE-sri-missing"));
    expect(sri.length).toBeGreaterThanOrEqual(2); // script + stylesheet
    expect(sri.every((f) => f.evidence[0]?.source === "public/index.html")).toBe(true);
  });
});

describe("Modül FE — çıktı sözleşmesi", () => {
  it("her bulgu OWASP A0x:2021 referansı taşır (owasp.ts eşleştirmesi buna dayanır)", () => {
    for (const f of vuln) {
      expect(f.references?.some((r) => /^OWASP A\d{2}:2021$/.test(r))).toBe(true);
    }
  });
  it("her bulgunun modülü FE", () => {
    expect(vuln.every((f) => f.module === "FE")).toBe(true);
  });
  it("SAST kural setinde artık module==='FE' kuralı yok (çift bulgu olmaz)", () => {
    expect(SAST_RULES.filter((r) => r.module === "FE")).toHaveLength(0);
  });
});

describe("Modül FE — FP muhafızı", () => {
  it("safe-fe hiç bulgu üretmemeli", () => {
    expect(scan("safe-fe").map((f) => f.id)).toEqual([]);
  });
});

describe("Modül FE — modül sözleşmesi", () => {
  it("pasif modül (aktif/yetki kapısı gerektirmez)", () => {
    expect(feModule.active).toBe(false);
    expect(feModule.id).toBe("FE");
  });
});

describe("scanner.ts — include/skip genişletmesi geriye uyumlu", () => {
  it("override verilmezse davranış birebir aynı", () => {
    const fs = createFsContext(fix("vuln-prisma-docker"));
    const a = scanSource(fs, SAST_RULES, { maxFiles: 200 });
    const b = scanSource(fs, SAST_RULES, { maxFiles: 200, include: CODE_FILE, skip: SKIP_PATH });
    expect(a.map((f) => f.fingerprint)).toEqual(b.map((f) => f.fingerprint));
  });
});

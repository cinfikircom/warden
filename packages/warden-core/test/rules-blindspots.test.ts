import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { createFsContext } from "../src/detect/fs.ts";
import { scanSource } from "../src/modules/sast/scanner.ts";
import { SAST_RULES } from "../src/modules/sast/rules.ts";
import { analyzeFe, collectFeData } from "../src/modules/fe/index.ts";
import { analyzeAccess, collectAccessData, extractRoutes } from "../src/modules/access/index.ts";
import { analyzeAuth, collectAuthData } from "../src/modules/auth/index.ts";
import { sastModule } from "../src/modules/sast/index.ts";
import { cweFor, FORBIDDEN_PARENTS } from "../src/risk/cwe.ts";
import { fpHintsFor } from "../src/risk/false-positives.ts";
import { loadRulePacks } from "../src/modules/sast/rule-packs.ts";
import { EMPTY_STACK } from "../src/model/module.ts";
import { AuditLog } from "../src/audit/log.ts";
import { DEFAULT_LIMITS } from "../src/authz/gate.ts";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

/**
 * Recall benchmark'ının ORTAYA ÇIKARDIĞI kör noktalar için regresyon testleri.
 *
 * Buradaki her senaryo `pnpm bench` çalıştırılırken NodeGoat'ta gerçekten kaçırılmış bir
 * zafiyete karşılık gelir. Testlerin amacı bu boşlukların sessizce geri gelmemesi.
 *
 * Not: bu dosya benchmark'ın YERİNE geçmez. Fixture testi kuralın çalıştığını gösterir;
 * kaçırmadığını yalnızca bağımsız korpus gösterir (bkz. benchmark/README.md).
 */

const FIX = join(import.meta.dirname, "fixtures");
const scan = (dir: string) =>
  scanSource(createFsContext(join(FIX, dir)), SAST_RULES, { maxFiles: 100 });

describe("B1 — camelCase secret anahtarları (NodeGoat'ta 6 kaçan)", () => {
  const findings = scan("vuln-gaps").filter((f) => f.evidence[0]?.source.includes("secrets-camel"));
  const excerpts = findings.map((f) => f.evidence[0]?.excerpt ?? "").join("\n");

  it.each([
    ["cookieSecret", "cookieSecret"],
    ["cryptoKey", "cryptoKey"],
    ["zapApiKey", "zapApiKey"],
    ["dbPassword", "dbPassword"],
  ])("%s yakalanır", (_ad, anahtar) => {
    expect(excerpts, `${anahtar} kaçtı — kelime-sınırı regresyonu`).toContain(anahtar);
  });

  /**
   * Yanlış pozitif koruması: değerin BOŞLUKSUZ olması şartı, "secret" içeren ama sır
   * olmayan alanları eler. Bu şart kaldırılırsa her açıklama metni sır sanılır.
   */
  it("boşluk içeren açıklama metni sır sayılmaz", () => {
    expect(excerpts).not.toContain("bu alan bir açıklama metnidir");
  });

  it("env'den okunan değer sır sayılmaz", () => {
    expect(excerpts).not.toContain("process.env.API_KEY");
  });
});

describe("B6 — ReDoS iç içe niceleyici (kural hiç yoktu, NodeGoat'ta 2 kaçan)", () => {
  const redos = scan("vuln-gaps").filter((f) => f.id.startsWith("B6-redos"));

  it("iç içe niceleyici yakalanır", () => {
    const excerpts = redos.map((f) => f.evidence[0]?.excerpt ?? "").join("\n");
    expect(excerpts, "([0-9]+)+ kalıbı kaçtı").toContain("([0-9]+)+");
  });

  /** Desen dar tutuldu: tek niceleyicili normal regex'ler bulgu üretmemeli. */
  it("lineer regex bulgu ÜRETMEZ", () => {
    const excerpts = redos.map((f) => f.evidence[0]?.excerpt ?? "").join("\n");
    expect(excerpts).not.toContain("[0-9]{5}");
  });

  /**
   * Regresyon: ilk desen iç içe GRUPLARI da iç içe niceleyici sanıyordu ve Warden'ın kendi
   * `risk/asvs.ts` dosyasındaki güvenli sürüm regex'ini yanlış pozitif olarak işaretledi.
   * İç grup ayrı bir karakter sınıfıyla (`\.`) ayrıldığında backtracking patlaması olmaz.
   */
  it("ayrılmış iç grup içeren güvenli regex bulgu ÜRETMEZ", () => {
    const safe = scanSource(createFsContext(join(FIX, "safe-app")), SAST_RULES, { maxFiles: 100 });
    expect(safe.filter((f) => f.id.startsWith("B6-redos"))).toHaveLength(0);
  });
});

describe("B6 — SSRF hedefi değişkenden geldiğinde (NodeGoat'ta 2 kaçan)", () => {
  const findings = scan("vuln-taint");
  const ssrf = findings.filter((f) => f.id.startsWith("B6-ssrf-node-var"));

  it("kullanıcı girdisinden türeyen URL ile yapılan istek yakalanır", () => {
    expect(ssrf.length, "taint zinciriyle gelen SSRF kaçtı").toBeGreaterThan(0);
    const lines = ssrf.map((f) => f.evidence[0]?.excerpt ?? "").join("\n");
    expect(lines).toContain("needle.get(url");
  });

  /**
   * `requiresTaint` sözleşmesinin can alıcı yarısı. Bu test olmasaydı kural her
   * `needle.get(x)` çağrısında bulgu üretir ve gerçek projelerde kullanılamaz olurdu.
   */
  it("sabit URL ile yapılan istek bulgu ÜRETMEZ", () => {
    const excerpts = ssrf.map((f) => f.evidence[0]?.excerpt ?? "").join("\n");
    expect(excerpts, "taint yokken bulgu üretildi — requiresTaint çalışmıyor").not.toContain(
      "status.internal.example.com",
    );
  });

  it("taint bulunduğu için güven 'low'un üstüne çıkar", () => {
    const first = ssrf[0];
    expect(first?.confidence).not.toBe("low");
    expect(first?.taint?.reached).toBe(true);
  });
});

describe("FE-8 — sunucu şablon motoru kaçışı (NodeGoat'ta 6 kaçan)", () => {
  const fe = (dir: string) => analyzeFe(collectFeData(createFsContext(join(FIX, dir))));
  const vuln = fe("vuln-template").filter((f) => f.check === "FE-8");

  it("autoescape: false yapılandırması yakalanır", () => {
    expect(vuln.some((f) => f.id.startsWith("FE-template-autoescape-off"))).toBe(true);
  });

  it("açık ham çıktı biçimleri yakalanır (|safe, {{{ }}}, marked())", () => {
    const ex = vuln.map((f) => f.evidence[0]?.excerpt ?? "").join("\n");
    expect(ex).toContain("marked(");
    expect(ex).toContain("| safe");
    expect(ex).toContain("{{{");
  });

  it("kaçış kapalıyken URL özniteliğine interpolasyon yakalanır", () => {
    expect(vuln.some((f) => f.id.startsWith("FE-template-url-interp"))).toBe(true);
  });

  /**
   * FP muhafızı: autoescape AÇIKKEN `href="{{ url }}"` normal ve güvenli bir kalıptır.
   * Bu ayrım olmasaydı kural her sunucu şablonunda bulgu üretir, kullanılamaz olurdu.
   */
  it("autoescape açıkken normal şablon bulgu ÜRETMEZ", () => {
    expect(fe("safe-template").filter((f) => f.check === "FE-8")).toHaveLength(0);
  });
});

describe("ACCESS — route envanteri (NodeGoat'ta 6 kaçan)", () => {
  const acc = analyzeAccess(collectAccessData(createFsContext(join(FIX, "vuln-routes"))));

  it("route tanımları ayrıştırılır (yol, metod, middleware zinciri)", () => {
    const routes = extractRoutes(
      'app.post("/x", isLoggedIn, h);\napp.get("/y/:userId", h2);',
    );
    expect(routes).toHaveLength(2);
    expect(routes[0]).toMatchObject({ method: "post", path: "/x" });
    expect(routes[0]?.middlewares).toContain("isLoggedIn");
    expect(routes[1]).toMatchObject({ method: "get", path: "/y/:userId" });
  });

  /**
   * Kritik: düzeltilmiş sürüm yorumda beklerken gerçek route korumasızdır. Yorumları
   * saymak, korumasız bir route'u korunmuş göstererek bulguyu yutardı.
   */
  it("yorum içindeki route tanımı sayılmaz", () => {
    const routes = extractRoutes('/* app.post("/gizli", isAdmin, h); */\napp.post("/acik", h);');
    expect(routes).toHaveLength(1);
    expect(routes[0]?.path).toBe("/acik");
  });

  it("auth middleware'i olmayan yazma route'u route düzeyinde yakalanır", () => {
    const hit = acc.find((f) => f.check === "ACC-2" && f.evidence[0]?.excerpt?.includes("/memos"));
    expect(hit, "korumasız POST /memos kaçtı").toBeDefined();
  });

  it("auth'lu yazma route'u bulgu ÜRETMEZ", () => {
    const ex = acc.filter((f) => f.check === "ACC-2").map((f) => f.evidence[0]?.excerpt ?? "").join("\n");
    expect(ex).not.toContain("/profile");
  });

  it("kimlik parametresi alan route IDOR olarak işaretlenir", () => {
    const idor = acc.find((f) => f.check === "ACC-1" && f.id.startsWith("ACC-1-idor-route"));
    expect(idor?.evidence[0]?.excerpt).toContain(":userId");
  });

  /**
   * Yol adı tahmin etmek yerine ölçülebilir olanı ölçüyoruz: auth var, rol yok.
   * Bir uygulamanın en ayrıcalıklı ucu `/benefits` gibi alana özgü bir ad taşıyabilir.
   */
  it("auth varken hiç rol kontrolü yoksa proje düzeyinde bulgu üretilir", () => {
    expect(acc.some((f) => f.id === "ACC-4-no-role-model")).toBe(true);
  });
});

describe("AUTH — parola akışı ve oturum (NodeGoat'ta 5 kaçan)", () => {
  const auth = (dir: string) => analyzeAuth(collectAuthData(createFsContext(join(FIX, dir))));
  const vuln = auth("vuln-authflow");
  const safe = auth("safe-authflow");

  /**
   * Kritik ayrım: `require("bcrypt")` satırı DURUYOR ama tek kullanımı yorumda.
   * Kullanılmayan bir import, uygulanmış bir koruma değildir.
   */
  it("AUTH-7 — import var ama hash ÇAĞRISI yoksa bulgu üretilir", () => {
    expect(vuln.some((f) => f.check === "AUTH-7")).toBe(true);
  });

  it("AUTH-7 — gerçekten hash'leyen projede bulgu ÜRETİLMEZ", () => {
    expect(safe.some((f) => f.check === "AUTH-7")).toBe(false);
  });

  it("AUTH-8 — girişte session.regenerate yoksa fixation bulgusu üretilir", () => {
    const f = vuln.find((x) => x.check === "AUTH-8");
    expect(f?.evidence[0]?.excerpt).toContain("req.session.userId");
  });

  it("AUTH-8 — regenerate varsa bulgu ÜRETİLMEZ", () => {
    expect(safe.some((f) => f.check === "AUTH-8")).toBe(false);
  });

  it("AUTH-9 — kullanıcı ve parola için ayrı hata mesajı enumeration sayılır", () => {
    expect(vuln.some((f) => f.check === "AUTH-9")).toBe(true);
  });

  /** Tek bir genel mesaj kullanan akış bulgu üretmemeli — kuralın can alıcı yarısı. */
  it("AUTH-9 — tek genel hata mesajı kullanılıyorsa bulgu ÜRETİLMEZ", () => {
    expect(safe.some((f) => f.check === "AUTH-9")).toBe(false);
  });
});

describe("B1 — depoya commit edilmiş anahtar dosyaları (NodeGoat'ta 1 kaçan)", () => {
  const run = async () => {
    const ctx = createFsContext(join(FIX, "vuln-keyfile"));
    return (await sastModule.run({
      projectRoot: join(FIX, "vuln-keyfile"),
      authz: { mode: "passive", authorizedTargets: [], authorizedBy: "", date: "", limits: DEFAULT_LIMITS, reasons: [], fileFound: false },
      audit: new AuditLog(join(mkdtempSync(join(tmpdir(), "warden-key-")), "run.log")),
      stack: EMPTY_STACK,
      fs: ctx,
    })).findings.filter((f) => f.id.startsWith("B1-committed-key-file"));
  };

  it("PEM özel anahtarı içeren .key dosyası yakalanır", async () => {
    const hits = await run();
    expect(hits.some((f) => f.evidence[0]?.source.endsWith("server.key"))).toBe(true);
  });

  /**
   * Uzantı tek başına yeterli değil: bazı projeler `.key` dosyasını lisans/i18n anahtarı
   * için kullanır. İçerik doğrulaması (PEM başlığı) bu ayrımı yapar.
   */
  it("PEM başlığı olmayan .key dosyası bulgu ÜRETMEZ", async () => {
    const hits = await run();
    expect(hits.some((f) => f.evidence[0]?.source.endsWith("license.key"))).toBe(false);
  });
});

describe("Strix devralma — CWE eşlemesi", () => {
  /**
   * Strix'in getirdiği asıl değerli kural: en spesifik child CWE kullanılır.
   * Parent CWE ("bir tür enjeksiyon") düzeltmeyi yönlendirmez ve uyum raporunda reddedilir.
   */
  it("hiçbir eşleme yasaklı parent CWE'ye çözülmez", () => {
    const samples = ["B6-sql-node", "B6-cmd-exec", "B6-ssrf-node-var", "ACC-2-route-no-auth", "PRIV-1-pii-in-logs"];
    for (const id of samples) {
      const cwe = cweFor({ id, check: id.split("-")[0] ?? "" });
      expect(FORBIDDEN_PARENTS, `${id} → ${cwe}`).not.toContain(cwe);
    }
  });

  it("aynı check altındaki farklı sınıflar farklı CWE alır", () => {
    expect(cweFor({ id: "B6-sql-node", check: "B6" })).toBe("CWE-89");
    expect(cweFor({ id: "B6-ssrf-node-var", check: "B6" })).toBe("CWE-918");
    expect(cweFor({ id: "B6-eval-node", check: "B6" })).toBe("CWE-95");
    expect(cweFor({ id: "B6-redos-nested-quantifier", check: "B6" })).toBe("CWE-1333");
  });

  it("eşleşme yoksa CWE uydurulmaz", () => {
    expect(cweFor({ id: "ZZZ-bilinmeyen", check: "ZZZ" })).toBeNull();
  });
});

describe("Strix devralma — doğrulama notları (False Positives)", () => {
  it("enjeksiyon bulgusu için doğrulama notu var", () => {
    expect(fpHintsFor({ id: "B6-sql-node", check: "B6" }).length).toBeGreaterThan(0);
  });

  it("notlar bulguyu bastırmaz — yalnızca metin döndürür", () => {
    const hints = fpHintsFor({ id: "B1-hardcoded-secret", check: "B1" });
    expect(hints.some((h) => h.toLowerCase().includes("placeholder"))).toBe(true);
  });
});

describe("Strix devralma — Rule Packs", () => {
  const load = (yml: string) => {
    const dir = mkdtempSync(join(tmpdir(), "warden-pack-"));
    mkdirSync(join(dir, "warden-rules"), { recursive: true });
    writeFileSync(join(dir, "warden-rules", "custom.yml"), yml, "utf8");
    return loadRulePacks(createFsContext(dir));
  };

  it("geçerli bildirimsel kural yüklenir", () => {
    const r = load(`rules:
  - id: CUSTOM-tenant
    module: ACCESS
    severity: P1
    title: withTenant sarmalayıcısı eksik
    pattern: "prisma\\\\.\\\\w+\\\\.findMany\\\\("
    impact: Kiracı filtresi olmadan sorgu.
    recommendation: withTenant() kullan.
`);
    expect(r.rules).toHaveLength(1);
    expect(r.rules[0]?.confidence).toBe("low"); // harici kural varsayılan düşük güven
  });

  /**
   * En kritik güvenlik sözleşmesi: kural dosyası KOD ÇALIŞTIRAMAZ. `validate` bir
   * fonksiyondur ve YAML'dan gelemez — gelebilseydi kural paketi indirmek RCE olurdu.
   */
  it("YAML'dan gelen `validate` alanı kurala GEÇMEZ", () => {
    const r = load(`rules:
  - id: EVIL
    module: B
    severity: P0
    title: kötücül
    pattern: "x"
    validate: "process.exit(1)"
    impact: x
    recommendation: x
`);
    expect(r.rules[0]).toBeDefined();
    expect((r.rules[0] as unknown as { validate?: unknown }).validate).toBeUndefined();
  });

  it("iç içe niceleyici içeren desen REDDEDİLİR (kendi motorumuzu kilitlemesin)", () => {
    const r = load(`rules:
  - id: REDOS
    module: B
    severity: P2
    title: redos
    pattern: "([0-9]+)+#"
    impact: x
    recommendation: x
`);
    expect(r.rules).toHaveLength(0);
    expect(r.warnings.join(" ")).toContain("ReDoS");
  });

  it("`g` bayrağı çıkarılır (test() stateful olup dosya atlatır)", () => {
    const r = load(`rules:
  - id: GFLAG
    module: B
    severity: P2
    title: g
    pattern: "abc"
    flags: "gi"
    impact: x
    recommendation: x
`);
    expect(r.rules[0]?.pattern.global).toBe(false);
    expect(r.rules[0]?.pattern.ignoreCase).toBe(true);
  });

  it("geçersiz modül/şiddet reddedilir ve UYARI üretir (sessiz atlama yok)", () => {
    const r = load(`rules:
  - id: BAD
    module: YOKMODUL
    severity: P9
    title: x
    pattern: "y"
    impact: x
    recommendation: x
`);
    expect(r.rules).toHaveLength(0);
    expect(r.warnings.length).toBeGreaterThan(0);
  });
});

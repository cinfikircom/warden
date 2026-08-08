import { readFileSync } from "node:fs";
import { AuditLog } from "./audit/log.ts";
import { evaluateAuthz } from "./authz/gate.ts";
import type { AuthzResult } from "./authz/gate.ts";
import { reportPaths, writeReport } from "./report/generator.ts";
import type { ReportPaths } from "./report/generator.ts";
import { computeDelta } from "./report/delta.ts";
import type { PreviousRun, Delta } from "./report/delta.ts";
import { CoverageCollector } from "./report/coverage.ts";
import type { CoverageManifest } from "./report/coverage.ts";
import { enrichRisk } from "./risk/score.ts";
import { enrichCwe } from "./risk/cwe.ts";
import { enrichKevEpss, loadKevData } from "./risk/kev.ts";
import { enrichReachability, buildImportGraph } from "./risk/reachability.ts";
import { loadWaivers, partitionWaived } from "./risk/waiver.ts";
import type { AppliedWaiver } from "./risk/waiver.ts";
import { buildAsvsChecklist } from "./risk/asvs.ts";
import { buildOwaspChecklist } from "./risk/owasp.ts";
import { buildCisChecklist, buildIsoChecklist } from "./risk/standards.ts";
import type { ScanContext, WardenModule } from "./model/module.ts";
import type { Finding, ModuleId } from "./model/finding.ts";
import { createFsContext } from "./detect/fs.ts";
import { resolveGitScope } from "./detect/scope.ts";
import type { ScanScope } from "./detect/scope.ts";
import { detectStack, defaultDetectors } from "./detect/registry.ts";
import type { StackDetector } from "./detect/types.ts";
import { defaultModules } from "./registry.ts";

// 0.12.0 — KAPSAM BEYANI turu (Faz A: dürüstlük).
//
// Warden artık yalnızca "ne buldum"u değil, "neyi göremedim"i de raporluyor. Eskiden motorun
// her katmanında sessiz kırpma vardı (derinlik, dosya sayısı, dosya boyutu, kural başına bulgu
// tavanı, çöken modül) ve hiçbiri rapora yansımıyordu — "bakamadım" ile "baktım, temiz" aynı
// görünüyordu. Bir güvenlik aracı için bu, kaçırılan zafiyetten daha tehlikelidir.
//
// ⚠ Kullanıcı-görünür değişiklik: yüzey bulamayan modül artık 10.0/10 yerine "kapsam dışı"
// alır ve genel ortalamaya GİRMEZ. Genel skor bu yüzden değişebilir — bu bir gerileme değil,
// ilk kez doğru sayının görülmesidir. Fingerprint'e dokunulmadı (K5): kapsam katmanı bulgu
// üretmez, bulgu bastırmaz; waiver'lar ve delta geçmişi aynen korunur.
//
// Gerekçe ve yol haritası: docs/DURUM-VE-GELECEK.md · devralma kararları: docs/STRIX-ADOPTION.md
export const WARDEN_VERSION = "0.12.0";

/** Önceki findings.json'ı PreviousRun'a çevirir. Yoksa/bozuksa null (ilk çalışma gibi davranır). */
function loadPreviousRun(findingsJsonPath: string): PreviousRun | null {
  let raw: string;
  try {
    raw = readFileSync(findingsJsonPath, "utf8");
  } catch {
    return null;
  }
  try {
    const o = JSON.parse(raw) as {
      generatedAt?: string;
      summary?: { overallScore?: number | null; parityScore?: number | null };
      findings?: Finding[];
    };
    return {
      findings: Array.isArray(o.findings) ? o.findings : [],
      overallScore: o.summary?.overallScore ?? null,
      parityScore: o.summary?.parityScore ?? null,
      generatedAt: o.generatedAt ?? null,
    };
  } catch {
    return null;
  }
}

export interface ScanOptions {
  readonly projectRoot: string;
  /** "scan" yalnızca pasif modülleri; "pentest" yetki kapısı açıksa aktif modülleri de koşar. */
  readonly intent: "scan" | "pentest";
  /** Modül kayıt defteri. Verilmezse yerleşik set. */
  readonly modules?: readonly WardenModule[];
  /** Dedektör seti. Verilmezse yerleşik set. */
  readonly detectors?: readonly StackDetector[];
  /**
   * Diff-scope tarama: verilen git referansından bu yana değişen dosyalarla sınırla
   * (ör. "HEAD~1", "origin/main"). Çözülemezse tarama TAM kapsamla sürer — kapsam
   * daraltması sessizce başarısız olup eksik denetimi tam denetim gibi göstermemeli.
   */
  readonly since?: string;
  /**
   * Dizin derinliği sınırını yükselt (varsayılan 6). Derin monorepo'larda
   * `apps/web/src/app/(dashboard)/admin/page.tsx` 7. seviyededir ve varsayılanla HİÇ görülmez.
   */
  readonly maxDepth?: number | undefined;
  /** Ağaç yürüyüşünde dosya sayısı tavanını yükselt (varsayılan 2000). */
  readonly maxFiles?: number | undefined;
}

export interface ScanResult {
  readonly mode: AuthzResult["mode"];
  readonly authz: AuthzResult;
  readonly findings: readonly Finding[];
  /** `.warden-ignore.yml` ile gerekçeli bastırılan bulgular (rapor/gate dışı, ama izlenir). */
  readonly waived: readonly AppliedWaiver[];
  readonly ranModules: ReadonlySet<ModuleId>;
  readonly artifacts: ReadonlyMap<ModuleId, unknown>;
  readonly delta: Delta;
  readonly paths: ReportPaths;
  readonly startedAt: string;
  readonly finishedAt: string;
  /**
   * Diff-scope uygulandıysa kapsam özeti; tam taramada null. CLI bunu "kısmi sonuç" uyarısı
   * göstermek ve delta'yı bastırmak için kullanır.
   */
  readonly scope: { readonly since: string; readonly fileCount: number } | null;
  /**
   * KAPSAM BEYANI — bu çalışmada neyin görülüp neyin görülmediği.
   * Bulguların yanında okunması gerekir: 0 bulgu, kapsam %40 ise "temiz" demek değildir.
   */
  readonly coverage: CoverageManifest;
}

/**
 * Ana orkestrasyon (iş emri §7). Pasif varsayılan; aktif modüller yalnızca
 * intent="pentest" VE yetki kapısı açıkken çalışır. Her karar audit log'a yazılır.
 */
export async function runScan(opts: ScanOptions): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const paths = reportPaths(opts.projectRoot);

  // Önceki çalışmayı (üzerine yazılmadan ÖNCE) oku — öncesi/sonrası delta için.
  const previous = loadPreviousRun(paths.findingsJson);

  const audit = new AuditLog(paths.runLog);
  audit.info(`Warden ${WARDEN_VERSION} başladı. Niyet: ${opts.intent}. Proje: ${opts.projectRoot}`);
  if (previous) audit.info(`Önceki çalışma bulundu (${previous.generatedAt ?? "?"}) — delta hesaplanacak.`);

  // 1) Yetki kapısı — her şeyden önce.
  const authz = evaluateAuthz(opts.projectRoot);
  for (const r of authz.reasons) audit.authz(r);

  const mode: AuthzResult["mode"] = opts.intent === "pentest" ? authz.mode : "passive";
  if (opts.intent === "pentest" && authz.mode !== "active") {
    audit.warn("pentest istendi ama yetki kapısı kapalı → yalnızca PASİF modüller çalışacak.");
  }
  audit.info(`Etkin mod: ${mode.toUpperCase()}`);

  // 2) Stack tespiti (plugin dedektörler).
  const detectors = opts.detectors ?? defaultDetectors();
  const stack = await detectStack(opts.projectRoot, detectors, (m) => audit.info(m));
  audit.info(
    `Stack: diller=[${stack.languages.join(",")}] framework=[${stack.frameworks.join(",")}] ` +
      `orm=[${stack.orm.join(",")}] cloud=[${stack.cloud.join(",")}] containerized=${stack.containerized}`,
  );

  // 2b) Diff-scope: kapsam daraltma yalnızca --since verildiğinde.
  let scope: ScanScope | null = null;
  if (opts.since !== undefined) {
    const r = resolveGitScope(opts.projectRoot, opts.since, audit);
    if (r.scope) {
      scope = r.scope;
      audit.info(`Diff-scope: "${opts.since}" referansından bu yana ${scope.paths.size} dosya kapsamda.`);
      if (scope.paths.size === 0) {
        audit.warn("Diff-scope kapsamı boş — değişen dosya yok, bulgu üretilmeyecek.");
      }
    } else {
      // Sessizce tam taramaya düşmek, kullanıcının "hızlı kısmi tarama" beklentisini
      // sessizce yavaş tam taramaya çevirirdi; tersi (kapsam yok sanıp eksik tarama) daha da
      // kötü olurdu. Bu yüzden gürültülü uyar ve TAM kapsamla devam et.
      audit.warn(`${r.error} Kapsam daraltılmadı; TAM tarama yapılıyor.`);
    }
  }

  const coverage = new CoverageCollector();
  const fs = createFsContext(opts.projectRoot, {
    scopePaths: scope?.paths,
    coverage,
    maxDepth: opts.maxDepth,
    maxFiles: opts.maxFiles,
  });
  const ctx: ScanContext = { projectRoot: opts.projectRoot, authz, audit, stack, fs, coverage };

  // 3) Modülleri koş.
  //
  // Her modülün akıbeti KAYDEDİLİR. Eskiden çöken modül ile hiç bulgu bulmayan modül raporda
  // ayırt edilemiyordu: ikisi de sessizdi ve boyut ya "n/d" ya da 10.0 görünüyordu. Yarısı
  // çökmüş bir tarama temiz rapor gibi okunabiliyordu.
  const modules = opts.modules ?? defaultModules();
  const findings: Finding[] = [];
  const ranModules = new Set<ModuleId>();
  const artifacts = new Map<ModuleId, unknown>();
  for (const mod of modules) {
    if (mod.active && mode !== "active") {
      audit.info(`Modül ${mod.id} (${mod.title}) atlandı: aktif modül + pasif mod.`);
      coverage.module({
        module: mod.id,
        title: mod.title,
        status: "not-run",
        reason: "Aktif (DAST) modül — yetki kapısı açık değil, hiç çalıştırılmadı.",
        surface: null,
        findings: 0,
      });
      continue;
    }
    if (!mod.applicable(ctx)) {
      audit.info(`Modül ${mod.id} (${mod.title}) atlandı: stack uyumsuz.`);
      coverage.module({
        module: mod.id,
        title: mod.title,
        status: "surface-absent",
        reason: "Bu projede ilgili yüzey bulunamadı (stack uyumsuz).",
        surface: 0,
        findings: 0,
      });
      continue;
    }
    audit.info(`Modül ${mod.id} (${mod.title}) çalışıyor...`);
    try {
      const out = await mod.run(ctx);
      findings.push(...out.findings);
      if (out.artifact !== undefined) artifacts.set(mod.id, out.artifact);
      ranModules.add(mod.id);
      audit.info(`Modül ${mod.id} bitti: ${out.findings.length} bulgu.`);
      const surface = out.surface ?? null;
      coverage.module({
        module: mod.id,
        title: mod.title,
        // Modül çalıştı ama tek bir gerçek yüzey öğesi bulamadıysa, bu "temiz" değil
        // "denetlenecek bir şey yoktu" demektir — skor tablosunda puan almamalı.
        status: surface === 0 ? "surface-absent" : "audited",
        reason: surface === 0 ? "Modül çalıştı ama denetlenecek somut bir yüzey öğesi bulamadı." : null,
        surface,
        findings: out.findings.length,
      });
    } catch (err) {
      // Bu boyut DENETLENMEDİ. Sessiz kalmak, denetlenmemişi temiz göstermek olurdu.
      audit.warn(`Modül ${mod.id} hata verdi, atlandı: ${String(err)}`);
      coverage.module({
        module: mod.id,
        title: mod.title,
        status: "failed",
        reason: `Modül hata verdi: ${String(err)}`,
        surface: null,
        findings: 0,
      });
    }
  }

  // Kapsam beyanının kendi sınırlarını da beyan et — bu katman kendi eksiğini gizlememeli.
  coverage.unmeasured(
    "Derinlik sınırında kesilen dizinlerin altında kaç dosya olduğu sayılmıyor; " +
      "atlanan dosya sayısı bu yüzden bilinen bir ALT SINIRDIR.",
  );
  coverage.unmeasured(
    "`exists()` / `readFile()` ile yapılan yokluk kontrolleri (ör. \"helmet kurulu mu\") " +
      "dosya kapsamı yüzdesine girmez — bunlar ağaç taraması değildir.",
  );

  const finishedAt = new Date().toISOString();

  // 4) Risk motoru: CVSS v4 + exploitability; ASVS + CIS + ISO checklist'leri.
  //    + KEV/EPSS önceliklendirme (çevrimdışı; warden-data/ anlık-görüntülerinden, ağsız).
  const kevData = loadKevData(opts.projectRoot);
  if (kevData.kev.size > 0 || kevData.epss.size > 0) {
    audit.info(`KEV/EPSS anlık-görüntüsü yüklendi (KEV=${kevData.kev.size}, EPSS=${kevData.epss.size}).`);
  }
  //    + reachability: zafiyetli bağımlılık kaynak import grafında mı (FP azaltma).
  const importGraph = buildImportGraph(fs);
  const enriched = enrichCwe(
    enrichReachability(enrichKevEpss(enrichRisk(findings), kevData.kev, kevData.epss), importGraph),
  );

  // 4b) Waiver: .warden-ignore.yml ile gerekçeli bastırılan bulguları ayır. Süresi
  //     geçmiş waiver'lar yok sayılır. Bastırılanlar rapor/gate dışı kalır ama log'lanır.
  const waiverLoad = loadWaivers(opts.projectRoot);
  for (const w of waiverLoad.warnings) audit.warn(w);
  const { active, waived } = partitionWaived(enriched, waiverLoad.waivers, startedAt);
  for (const w of waived) {
    audit.info(`Waived: ${w.finding.id} (${w.finding.severity}) — gerekçe: ${w.reason}`);
  }
  if (waived.length > 0) audit.info(`Toplam ${waived.length} bulgu .warden-ignore.yml ile bastırıldı.`);

  // OWASP Top 10 başa: raporun "Uyum Özeti" tablosunda en üstte görünmeli.
  const extraChecklists = [buildOwaspChecklist(active), buildAsvsChecklist(active), buildCisChecklist(active), buildIsoChecklist(active)];

  // Reachability için import grafı kurulurken de ağaç yürünür; o okumalar da kapsama sayılır.
  const manifest = coverage.build();
  if (manifest.limits.length > 0) {
    audit.warn(
      `Kapsam kaybı: ${manifest.limits.map((l) => `${l.kind}×${l.count}`).join(", ")} — ` +
        "ayrıntı raporun Kapsam Beyanı bölümünde.",
    );
  }

  // 5) Rapor üret.
  writeReport(active, {
    projectRoot: opts.projectRoot,
    mode,
    authz,
    ranModules,
    artifacts,
    previous,
    extraChecklists,
    startedAt,
    finishedAt,
    wardenVersion: WARDEN_VERSION,
    scope: scope ? { since: scope.since, fileCount: scope.paths.size } : undefined,
    coverage: manifest,
  });
  audit.info(`Rapor yazıldı: ${paths.dir}`);
  if (scope) {
    audit.info("Kısmi tarama: findings.json ve history.jsonl bilerek güncellenmedi (tam postür kaydı korunur).");
  }

  /*
   * Kısmi taramada delta HESAPLANMAZ.
   *
   * `previous` tam bir taramanın kaydı; bu çalışma ise dosyaların bir alt kümesini gördü.
   * İkisini karşılaştırmak, taranmamış dosyalardaki her bulguyu "düzeltildi" diye raporlardı —
   * bir güvenlik aracının üretebileceği en tehlikeli yanlış sinyal. Boş delta, yanlış delta'dan
   * iyidir.
   */
  const delta = scope ? computeDelta(null, active) : computeDelta(previous, active);
  return {
    mode,
    authz,
    findings: active,
    waived,
    ranModules,
    artifacts,
    delta,
    paths,
    startedAt,
    finishedAt,
    scope: scope ? { since: scope.since, fileCount: scope.paths.size } : null,
    coverage: manifest,
  };
}

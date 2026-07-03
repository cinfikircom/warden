import { readFileSync } from "node:fs";
import { AuditLog } from "./audit/log.ts";
import { evaluateAuthz } from "./authz/gate.ts";
import type { AuthzResult } from "./authz/gate.ts";
import { reportPaths, writeReport } from "./report/generator.ts";
import type { ReportPaths } from "./report/generator.ts";
import { computeDelta } from "./report/delta.ts";
import type { PreviousRun, Delta } from "./report/delta.ts";
import { enrichRisk } from "./risk/score.ts";
import { enrichKevEpss, loadKevData } from "./risk/kev.ts";
import { enrichReachability, buildImportGraph } from "./risk/reachability.ts";
import { loadWaivers, partitionWaived } from "./risk/waiver.ts";
import type { AppliedWaiver } from "./risk/waiver.ts";
import { buildAsvsChecklist } from "./risk/asvs.ts";
import { buildCisChecklist, buildIsoChecklist } from "./risk/standards.ts";
import type { ScanContext, WardenModule } from "./model/module.ts";
import type { Finding, ModuleId } from "./model/finding.ts";
import { createFsContext } from "./detect/fs.ts";
import { detectStack, defaultDetectors } from "./detect/registry.ts";
import type { StackDetector } from "./detect/types.ts";
import { defaultModules } from "./registry.ts";

export const WARDEN_VERSION = "0.9.0";

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

  const fs = createFsContext(opts.projectRoot);
  const ctx: ScanContext = { projectRoot: opts.projectRoot, authz, audit, stack, fs };

  // 3) Modülleri koş.
  const modules = opts.modules ?? defaultModules();
  const findings: Finding[] = [];
  const ranModules = new Set<ModuleId>();
  const artifacts = new Map<ModuleId, unknown>();
  for (const mod of modules) {
    if (mod.active && mode !== "active") {
      audit.info(`Modül ${mod.id} (${mod.title}) atlandı: aktif modül + pasif mod.`);
      continue;
    }
    if (!mod.applicable(ctx)) {
      audit.info(`Modül ${mod.id} (${mod.title}) atlandı: stack uyumsuz.`);
      continue;
    }
    audit.info(`Modül ${mod.id} (${mod.title}) çalışıyor...`);
    try {
      const out = await mod.run(ctx);
      findings.push(...out.findings);
      if (out.artifact !== undefined) artifacts.set(mod.id, out.artifact);
      ranModules.add(mod.id);
      audit.info(`Modül ${mod.id} bitti: ${out.findings.length} bulgu.`);
    } catch (err) {
      audit.warn(`Modül ${mod.id} hata verdi, atlandı: ${String(err)}`);
    }
  }

  const finishedAt = new Date().toISOString();

  // 4) Risk motoru: CVSS v4 + exploitability; ASVS + CIS + ISO checklist'leri.
  //    + KEV/EPSS önceliklendirme (çevrimdışı; warden-data/ anlık-görüntülerinden, ağsız).
  const kevData = loadKevData(opts.projectRoot);
  if (kevData.kev.size > 0 || kevData.epss.size > 0) {
    audit.info(`KEV/EPSS anlık-görüntüsü yüklendi (KEV=${kevData.kev.size}, EPSS=${kevData.epss.size}).`);
  }
  //    + reachability: zafiyetli bağımlılık kaynak import grafında mı (FP azaltma).
  const importGraph = buildImportGraph(fs);
  const enriched = enrichReachability(
    enrichKevEpss(enrichRisk(findings), kevData.kev, kevData.epss),
    importGraph,
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

  const extraChecklists = [buildAsvsChecklist(active), buildCisChecklist(active), buildIsoChecklist(active)];

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
  });
  audit.info(`Rapor yazıldı: ${paths.dir}`);

  const delta = computeDelta(previous, active);
  return { mode, authz, findings: active, waived, ranModules, artifacts, delta, paths, startedAt, finishedAt };
}

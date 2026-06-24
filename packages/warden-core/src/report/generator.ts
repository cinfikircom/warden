import { mkdirSync, writeFileSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../model/finding.ts";
import { SEVERITIES, SEVERITY_EMOJI, severityRank } from "../model/severity.ts";
import type { Severity } from "../model/severity.ts";
import type { AuthzResult } from "../authz/gate.ts";
import { buildScoreboard, overallScore } from "./scoreboard.ts";
import type { ModuleId } from "../model/finding.ts";
import { maskSecrets } from "../secret/mask.ts";
import { toSarif } from "./sarif.ts";
import { PARITY_EMOJI } from "../model/parity.ts";
import type { ParityResult } from "../model/parity.ts";
import { computeDelta, renderDeltaSection, historyLine } from "./delta.ts";
import type { PreviousRun } from "./delta.ts";
import { COMPLIANCE_EMOJI, checklistScore } from "../model/compliance.ts";
import type { ComplianceResult, Checklist } from "../model/compliance.ts";

export interface ReportMeta {
  readonly projectRoot: string;
  readonly mode: AuthzResult["mode"];
  readonly authz: AuthzResult;
  readonly ranModules: ReadonlySet<ModuleId>;
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly wardenVersion: string;
  /** Modüllerin döndürdüğü yapısal artifact'ler (ör. "A" → ParityResult). */
  readonly artifacts?: ReadonlyMap<ModuleId, unknown>;
  /** Önceki çalışmanın özeti (öncesi/sonrası delta için). İlk çalışmada null. */
  readonly previous?: PreviousRun | null;
  /** Risk motorunun ürettiği ek checklist'ler (ASVS, CIS, ISO 27001). */
  readonly extraChecklists?: readonly Checklist[];
}

export interface ReportPaths {
  readonly dir: string;
  readonly reportMd: string;
  readonly findingsJson: string;
  readonly remediationMd: string;
  readonly parityMd: string;
  readonly complianceMd: string;
  readonly sarif: string;
  readonly history: string;
  readonly runLog: string;
}

export function reportPaths(projectRoot: string): ReportPaths {
  const dir = join(projectRoot, "warden-report");
  return {
    dir,
    reportMd: join(dir, "report.md"),
    findingsJson: join(dir, "findings.json"),
    remediationMd: join(dir, "remediation-playbook.md"),
    parityMd: join(dir, "parity-report.md"),
    complianceMd: join(dir, "compliance-report.md"),
    sarif: join(dir, "findings.sarif"),
    history: join(dir, "history.jsonl"),
    runLog: join(dir, "warden-run.log"),
  };
}

function parityScoreOf(meta: ReportMeta): number | null {
  return parityArtifact(meta)?.overall ?? null;
}

function complianceArtifact(meta: ReportMeta): ComplianceResult | null {
  const a = meta.artifacts?.get("D");
  if (a && typeof a === "object" && "checklists" in a) return a as ComplianceResult;
  return null;
}

/** Uyum + ASVS checklist'lerinin birleşik listesi. */
function allChecklists(meta: ReportMeta): Checklist[] {
  return [...(complianceArtifact(meta)?.checklists ?? []), ...(meta.extraChecklists ?? [])];
}

function renderComplianceMd(meta: ReportMeta): string {
  const lists = allChecklists(meta);
  const lines: string[] = [];
  lines.push("# Uyum Raporu (Modül D + ASVS)");
  lines.push("");
  lines.push("> ✔ Passed · ⚠ Partial · ✖ Failed · – Unknown (manuel/canlı doğrulama gerekir).");
  lines.push("");
  if (lists.length === 0) {
    lines.push("_Bu çalışmada uyum checklist'i üretilmedi._");
    return lines.join("\n");
  }
  for (const list of lists) {
    const s = checklistScore(list);
    lines.push(`## ${list.name} — ${s.pct === null ? "n/d" : `%${s.pct}`} (✔${s.passed} ⚠${s.partial} ✖${s.failed})`);
    lines.push("");
    lines.push("| Kontrol | Madde | Durum | Not |");
    lines.push("|---------|-------|:-----:|-----|");
    for (const it of list.items) {
      lines.push(`| ${it.control} | ${it.title} | ${COMPLIANCE_EMOJI[it.status]} | ${it.note} |`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

function parityArtifact(meta: ReportMeta): ParityResult | null {
  const a = meta.artifacts?.get("A");
  if (a && typeof a === "object" && "layers" in a) return a as ParityResult;
  return null;
}

function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.id.localeCompare(b.id));
}

function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { P0: 0, P1: 0, P2: 0, P3: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

function renderReportMd(findings: readonly Finding[], meta: ReportMeta): string {
  const sorted = sortFindings(findings);
  const counts = countBySeverity(findings);
  const rows = buildScoreboard(findings, meta.ranModules);
  const overall = overallScore(rows);

  const lines: string[] = [];
  lines.push("# Warden Denetim Raporu");
  lines.push("");
  lines.push(`> Proje: \`${meta.projectRoot}\``);
  lines.push(`> Mod: **${meta.mode === "active" ? "AKTİF (yetki kapısı açık)" : "PASİF (read-only)"}**`);
  lines.push(`> Başlangıç: ${meta.startedAt} · Bitiş: ${meta.finishedAt} · Warden ${meta.wardenVersion}`);
  lines.push("");

  // Güvenlik ilkeleri hatırlatması (iş emri §2: skill açılış çıktısında da tekrarlanmalı).
  lines.push("> ⛔ **Güvenlik ilkeleri:** Varsayılan read-only. Aktif testler yalnızca yetki kapısı");
  lines.push("> (`warden.authz.yml`) açıkken, allow-list host'lara, rate-limited çalışır. Secret'lar maskelidir.");
  lines.push("");

  lines.push("## Yönetici Özeti");
  lines.push("");
  if (findings.length === 0) {
    lines.push("Bu çalışmada bulgu üretilmedi.");
    if (meta.ranModules.size === 0) {
      lines.push("");
      lines.push("_Henüz hiçbir denetim modülü etkin değil (Faz 0 iskeleti). Sonraki fazlarda modüller eklenecek._");
    }
  } else {
    lines.push(
      `Toplam **${findings.length}** bulgu: ` +
        SEVERITIES.map((s) => `${SEVERITY_EMOJI[s]} ${s}: **${counts[s]}**`).join(" · "),
    );
  }
  lines.push("");

  // Skor tablosu
  lines.push("## Skor Tablosu");
  lines.push("");
  lines.push("| Boyut | Skor /10 | Bulgu | P0 | P1 |");
  lines.push("|-------|:--------:|:-----:|:--:|:--:|");
  for (const r of rows) {
    const score = r.score === null ? "n/d" : r.score.toFixed(1);
    lines.push(`| ${r.dimension} | ${score} | ${r.findings} | ${r.p0} | ${r.p1} |`);
  }
  lines.push(`| **Genel** | **${overall === null ? "n/d" : overall.toFixed(1)}** | ${findings.length} | ${counts.P0} | ${counts.P1} |`);
  lines.push("");
  lines.push("_\"n/d\": bu boyut bu çalışmada değerlendirilmedi (modül çalışmadı)._");
  lines.push("");

  // Uyum özeti (PCI-DSS / Privacy / ASVS checklist'leri)
  const lists = allChecklists(meta);
  if (lists.length > 0) {
    lines.push("## Uyum Özeti");
    lines.push("");
    lines.push("| Standart | Skor | ✔ | ⚠ | ✖ |");
    lines.push("|----------|:----:|:-:|:-:|:-:|");
    for (const list of lists) {
      const s = checklistScore(list);
      lines.push(`| ${list.name} | ${s.pct === null ? "n/d" : `%${s.pct}`} | ${s.passed} | ${s.partial} | ${s.failed} |`);
    }
    lines.push("");
    lines.push("_Ayrıntı: `compliance-report.md`._");
    lines.push("");
  }

  // Değişim (öncesi → sonrası)
  const delta = computeDelta(meta.previous ?? null, findings);
  for (const l of renderDeltaSection(delta, meta.previous ?? null, overall, parityScoreOf(meta))) lines.push(l);

  // Bulgular
  lines.push("## Bulgular (şiddet sırasına göre)");
  lines.push("");
  if (sorted.length === 0) {
    lines.push("_Bulgu yok._");
  } else {
    for (const f of sorted) {
      lines.push(`### ${SEVERITY_EMOJI[f.severity]} [${f.severity}] ${f.title}`);
      lines.push("");
      lines.push(`- **ID:** \`${f.id}\` · **Kontrol:** ${f.check} · **Kategori:** ${f.category} · **Güven:** ${f.confidence}`);
      if (f.cvss !== undefined) lines.push(`- **CVSS v4:** ${f.cvss.toFixed(1)}${f.exploitability ? ` · **Exploitability:** ${f.exploitability}` : ""}`);
      if (f.references && f.references.length > 0) lines.push(`- **Eşleştirme:** ${f.references.join(", ")}`);
      lines.push(`- **Etki:** ${maskSecrets(f.impact)}`);
      lines.push(`- **Öneri:** ${maskSecrets(f.recommendation)} _(efor: ${f.effort}${f.autoFixable ? ", otomatik-düzeltilebilir" : ""})_`);
      if (f.evidence.length > 0) {
        lines.push("- **Kanıt:**");
        for (const e of f.evidence) {
          const loc = `${e.source}${e.location ? `:${e.location}` : ""}`;
          lines.push(`  - _(${e.type})_ \`${loc}\`${e.excerpt ? ` — ${maskSecrets(e.excerpt)}` : ""}`);
        }
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}

function renderFindingsJson(findings: readonly Finding[], meta: ReportMeta): string {
  const rows = buildScoreboard(findings, meta.ranModules);
  const delta = computeDelta(meta.previous ?? null, findings);
  return JSON.stringify(
    {
      warden: meta.wardenVersion,
      generatedAt: meta.finishedAt,
      mode: meta.mode,
      projectRoot: meta.projectRoot,
      summary: {
        total: findings.length,
        bySeverity: countBySeverity(findings),
        overallScore: overallScore(rows),
        parityScore: parityScoreOf(meta),
        maxCvss: findings.reduce((m, f) => Math.max(m, f.cvss ?? 0), 0),
      },
      checklists: allChecklists(meta),
      delta: {
        isFirstRun: delta.isFirstRun,
        fixed: delta.fixed.map((f) => f.fingerprint),
        introduced: delta.introduced.map((f) => f.fingerprint),
        persisting: delta.persisting.map((f) => f.fingerprint),
        previousGeneratedAt: meta.previous?.generatedAt ?? null,
        previousOverallScore: meta.previous?.overallScore ?? null,
      },
      scoreboard: rows,
      findings: sortFindings(findings),
    },
    null,
    2,
  );
}

function renderRemediationMd(findings: readonly Finding[], meta: ReportMeta): string {
  const actionable = sortFindings(findings).filter((f) => f.severity === "P0" || f.severity === "P1");
  const lines: string[] = [];
  lines.push("# Remediation Playbook");
  lines.push("");
  lines.push("> Her P0/P1 bulgusu için **kopyala-yapıştır Claude Code prompt'u**. Düzeltmeyi");
  lines.push("> Warden uygulamaz; bu prompt'ları ayrı bir Claude Code ajanına verirsiniz (iş emri §5.3).");
  lines.push("");
  if (actionable.length === 0) {
    lines.push("_Bu çalışmada P0/P1 bulgusu yok._");
    return lines.join("\n");
  }
  for (const f of actionable) {
    const risk = `${f.cvss !== undefined ? `CVSS ${f.cvss.toFixed(1)}` : f.severity}${f.exploitability ? ` / exploitability ${f.exploitability}` : ""}`;
    lines.push(`## [${f.severity}] ${f.title} (\`${f.id}\`) — ${risk}`);
    lines.push("");
    lines.push("```text");
    lines.push(`Görev: Aşağıdaki güvenlik bulgusunu düzelt (Warden denetimi).`);
    lines.push(`Bulgu: ${f.title}`);
    lines.push(`Şiddet/Risk: ${f.severity} · ${risk} · güven: ${f.confidence}`);
    lines.push(`Kategori/Kontrol: ${f.category} (${f.check})`);
    if (f.references && f.references.length > 0) lines.push(`Standart: ${f.references.join(", ")}`);
    lines.push(`Etki: ${maskSecrets(f.impact)}`);
    lines.push(`Etkilenen konum(lar):`);
    if (f.evidence.length > 0) {
      for (const e of f.evidence) lines.push(`  - ${e.source}${e.location ? `:${e.location}` : ""}`);
    } else {
      lines.push(`  - (rapora bakın)`);
    }
    lines.push(`Adımlar:`);
    lines.push(`  1) Yukarıdaki konum(lar)ı aç ve sorunu doğrula.`);
    lines.push(`  2) Şu yaklaşımı uygula: ${maskSecrets(f.recommendation)}`);
    lines.push(`  3) Aynı sınıftaki diğer örnekleri de tara (grep ile yaygınlaştır).`);
    lines.push(`Test/Kabul:`);
    lines.push(`  - İlgili birim/entegrasyon testini ekle/güncelle; regresyon olmamalı.`);
    lines.push(`  - Warden'i yeniden çalıştır: bu bulgu (\`${f.id}\`) "düzeltilen"e geçmeli (öncesi/sonrası delta).`);
    lines.push("```");
    lines.push("");
  }
  return lines.join("\n");
}

function renderParityMd(findings: readonly Finding[], meta: ReportMeta): string {
  const lines: string[] = [];
  lines.push("# Parity Raporu (Modül A)");
  lines.push("");
  lines.push("> Local ↔ production farkı: ✅ uyumlu · 🟡 dikkat · 🔴 drift/risk · ⏳ doğrulanamadı (canlı veri gerekir).");
  lines.push("");

  const parity = parityArtifact(meta);
  if (!parity) {
    lines.push("_Modül A bu çalışmada etkin değil._");
    return lines.join("\n");
  }

  lines.push(`## PARITY SCORE: ${parity.overall === null ? "n/d" : `${parity.overall.toFixed(1)} / 10`}`);
  lines.push("");
  for (const l of parity.layers) {
    const scoreTxt = l.score === null ? "n/d" : `${l.score.toFixed(1)}/10`;
    lines.push(`### ${l.code} ${l.name}`);
    lines.push(`${PARITY_EMOJI[l.status]} ${l.note} _(skor: ${scoreTxt})_`);
    const layerFindings = findings.filter((f) => l.findingIds.includes(f.id));
    for (const f of layerFindings) {
      lines.push(`  - ${SEVERITY_EMOJI[f.severity]} [${f.severity}] ${maskSecrets(f.title)}`);
    }
    lines.push("");
  }

  lines.push("| Katman | Durum | Skor | Bulgu |");
  lines.push("|--------|:-----:|:----:|:-----:|");
  for (const l of parity.layers) {
    lines.push(`| ${l.code} ${l.name} | ${PARITY_EMOJI[l.status]} | ${l.score === null ? "n/d" : l.score.toFixed(1)} | ${l.findingIds.length} |`);
  }
  return lines.join("\n");
}

/** Tüm rapor dosyalarını `warden-report/` altına yazar. */
export function writeReport(findings: readonly Finding[], meta: ReportMeta): ReportPaths {
  const paths = reportPaths(meta.projectRoot);
  mkdirSync(paths.dir, { recursive: true });
  writeFileSync(paths.reportMd, renderReportMd(findings, meta), "utf8");
  writeFileSync(paths.findingsJson, renderFindingsJson(findings, meta), "utf8");
  writeFileSync(paths.remediationMd, renderRemediationMd(findings, meta), "utf8");
  writeFileSync(paths.parityMd, renderParityMd(findings, meta), "utf8");
  writeFileSync(paths.complianceMd, renderComplianceMd(meta), "utf8");
  writeFileSync(paths.sarif, toSarif(findings, meta.wardenVersion), "utf8");

  // history.jsonl — trend için her çalışmadan tek satır.
  const rows = buildScoreboard(findings, meta.ranModules);
  const delta = computeDelta(meta.previous ?? null, findings);
  appendFileSync(
    paths.history,
    historyLine(meta.finishedAt, overallScore(rows), parityScoreOf(meta), findings, delta) + "\n",
    "utf8",
  );
  return paths;
}

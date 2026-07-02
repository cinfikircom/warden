import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import { sarifToFindings } from "../../adapters/sarif.ts";
import { osvToFindings, runOsvScanner } from "../../adapters/osv.ts";
import { runPassiveTools, enabledTools } from "../../adapters/native-tools.ts";

/**
 * Dış Araç İçe-Aktarım Modülü (orkestratör katmanı). Warden'ı en-iyi motorlarla birleştirir:
 * kullanıcı CI'da `semgrep/opengrep/trivy/gitleaks/checkov --sarif > warden-imports/x.sarif`
 * (veya `osv-scanner --format json > warden-imports/x.osv.json`) üretir; bu modül çıktıyı
 * Warden'ın Finding modeline normalize eder — böylece fingerprint/delta, skorlama, playbook,
 * waiver ve SARIF re-export bu bulgulara da uygulanır.
 *
 * Non-intrusive: yalnızca `warden-imports/` dizini varsa veya WARDEN_OSV=1 ile çalışır;
 * aksi halde varsayılan tarama değişmez. Bulgular SAST boyutuna (module "B") atanır.
 */

const IMPORT_DIR = "warden-imports";
const SARIF_RE = new RegExp(`^${IMPORT_DIR}/.*\\.sarif(\\.json)?$`, "i");
const OSV_RE = new RegExp(`^${IMPORT_DIR}/.*\\.osv\\.json$`, "i");

function osvEnabled(): boolean {
  const v = process.env["WARDEN_OSV"];
  return v === "1" || v === "true";
}

export const importsModule: WardenModule = {
  id: "B",
  title: "Dış Araç İçe-Aktarımı (SARIF/OSV)",
  active: false,
  applicable(ctx: ScanContext): boolean {
    if (osvEnabled()) return true;
    const tools = enabledTools();
    if (tools === "all" || tools.size > 0) return true;
    // warden-imports/ altında en az bir içe-aktarılabilir dosya var mı?
    const hits = ctx.fs.find((p) => SARIF_RE.test(p) || OSV_RE.test(p), { limit: 1 });
    return hits.length > 0;
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const findings: Finding[] = [];

    const files = ctx.fs.find((p) => SARIF_RE.test(p) || OSV_RE.test(p), { limit: 200 });
    for (const file of files) {
      const text = ctx.fs.readFile(file);
      if (!text) continue;
      const before = findings.length;
      if (OSV_RE.test(file)) findings.push(...osvToFindings(text));
      else findings.push(...sarifToFindings(text, { sourceLabel: file }));
      ctx.audit.info(`İçe-aktarıldı: ${file} → ${findings.length - before} bulgu.`);
    }

    // Opsiyonel: osv-scanner kuruluysa canlı çalıştır (çok-ekosistem SCA).
    if (osvEnabled()) {
      const osv = runOsvScanner(ctx.projectRoot, ctx.audit);
      findings.push(...osv.findings);
      if (osv.ran) ctx.audit.info(`osv-scanner: ${osv.findings.length} bağımlılık bulgusu.`);
    }

    // Opsiyonel: WARDEN_TOOLS ile istenen native pasif araçları (opengrep/trivy/gitleaks/checkov) çalıştır.
    findings.push(...runPassiveTools(ctx.projectRoot, ctx.audit));

    // Fingerprint bazında dedup (aynı bulgu birden çok araçtan gelebilir).
    const seen = new Set<string>();
    const deduped = findings.filter((f) => (seen.has(f.fingerprint) ? false : (seen.add(f.fingerprint), true)));
    ctx.audit.info(`Dış araç içe-aktarımı: ${deduped.length} bulgu (${files.length} dosya).`);
    return { findings: deduped };
  },
};

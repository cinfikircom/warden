import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import { scanSource } from "./scanner.ts";
import { SAST_RULES } from "./rules.ts";
import { collectAuditFindings } from "./dependency.ts";
import { makeFinding } from "../../util/finding.ts";
import { looksLikeSecret } from "../../secret/mask.ts";

/**
 * Modül B — Statik Uygulama Güvenliği (SAST, pasif/read-only).
 * B1 secret · B2 bağımlılık · B3 kripto · B4/FE auth · B5 authz · B6 injection · B7/B9 sertleştirme.
 * Çoğu kontrol bildirimsel kural setinden (rules.ts) gelir; B2 canlı audit'i sarmalar.
 */
export const sastModule: WardenModule = {
  id: "B",
  title: "Statik Uygulama Güvenliği (SAST)",
  active: false,
  applicable() {
    return true; // kaynak kodu olan her projede anlamlı.
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const findings: Finding[] = [];

    // Bildirimsel kaynak kuralları (B1/B3/B4/B5/B6/B7/B9/FE).
    findings.push(...scanSource(ctx.fs, SAST_RULES));

    // Commit'lenmiş .env içinde gerçek secret (B1).
    const envText = ctx.fs.readFile(".env");
    if (envText && looksLikeSecret(envText)) {
      findings.push(
        makeFinding({
          id: "B1-committed-dotenv",
          title: "Depoda .env dosyası gerçek secret içeriyor olabilir",
          severity: "P1",
          module: "B",
          check: "B1",
          category: "Secret",
          confidence: "medium",
          evidence: [{ type: "file", source: ".env", excerpt: "secret-benzeri değer tespit edildi (maskeli)" }],
          impact: ".env repoda ise secret'lar paylaşılır/sızar.",
          recommendation: ".env'i .gitignore'a al; geçmişten temizle; değerleri rotasyon yap.",
          effort: "S",
          autoFixable: false,
          references: ["OWASP A07:2021"],
        }),
      );
    }

    // B2 bağımlılık zafiyetleri (best-effort, ağ gerektirir).
    const dep = collectAuditFindings(ctx.projectRoot, ctx.fs, ctx.audit);
    findings.push(...dep.findings);
    if (!dep.ran) ctx.audit.info("B2 dependency audit atlandı (lockfile yok ya da ağ erişimi yok).");

    ctx.audit.info(`SAST: ${findings.length} bulgu (kural seti + ${dep.ran ? "audit" : "audit yok"}).`);
    return { findings };
  },
};

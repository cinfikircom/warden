import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import type { Severity } from "../../model/severity.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

/**
 * Modül CLOUD — Cloud/IaC güvenliği (pasif, statik; Terraform odaklı).
 * AWS public S3 / IAM wildcard / açık security group / public RDS · Azure public storage · Cloudflare SSL.
 */

interface CloudRule {
  readonly id: string;
  readonly check: string;
  readonly title: string;
  readonly severity: Severity;
  readonly provider: string;
  readonly pattern: RegExp;
  readonly impact: string;
  readonly recommendation: string;
}

const RULES: readonly CloudRule[] = [
  {
    id: "CLOUD-AWS-s3-public", check: "CLOUD-AWS", title: "Public S3 bucket ACL", severity: "P0", provider: "AWS",
    pattern: /\bacl\s*=\s*"public-read(-write)?"/,
    impact: "Public S3 herkese okuma/yazma açar; veri sızıntısı.", recommendation: "ACL'i private yap; public access block'u etkinleştir.",
  },
  {
    id: "CLOUD-AWS-s3-no-block", check: "CLOUD-AWS", title: "S3 public access block kapalı", severity: "P1", provider: "AWS",
    pattern: /\bblock_public_(acls|policy)\s*=\s*false/,
    impact: "Public access block kapalıyken bucket yanlışlıkla açılabilir.", recommendation: "block_public_acls/policy = true.",
  },
  {
    id: "CLOUD-AWS-iam-wildcard", check: "CLOUD-AWS", title: "IAM wildcard izni (Action/Resource '*')", severity: "P1", provider: "AWS",
    pattern: /("?(Action|Resource)"?\s*[:=]\s*\[?\s*"\*")|actions\s*=\s*\[\s*"\*"\s*\]/,
    impact: "Wildcard izin en az yetki ilkesini ihlal eder; ele geçirilen kimlik her şeyi yapar.", recommendation: "Eylem/kaynakları daralt; least-privilege.",
  },
  {
    id: "CLOUD-AWS-sg-open", check: "CLOUD-AWS", title: "Security group dünyaya açık (0.0.0.0/0)", severity: "P1", provider: "AWS",
    pattern: /cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"/,
    impact: "0.0.0.0/0 ingress servisi tüm internete açar.", recommendation: "CIDR'ı bilinen IP'lere daralt; yönetim portlarını kapat.",
  },
  {
    id: "CLOUD-AWS-rds-public", check: "CLOUD-AWS", title: "RDS publicly_accessible = true", severity: "P1", provider: "AWS",
    pattern: /publicly_accessible\s*=\s*true/,
    impact: "Veritabanı internetten erişilebilir; saldırı yüzeyi.", recommendation: "publicly_accessible = false; özel subnet + SG.",
  },
  {
    id: "CLOUD-AZ-storage-public", check: "CLOUD-AZ", title: "Azure Storage public erişim açık", severity: "P1", provider: "Azure",
    pattern: /(allow_blob_public_access|allow_nested_items_to_be_public)\s*=\s*true/,
    impact: "Blob public erişimi veri sızıntısına yol açar.", recommendation: "Public blob erişimini kapat; SAS/RBAC kullan.",
  },
  {
    id: "CLOUD-CF-ssl-flexible", check: "CLOUD-CF", title: "Cloudflare SSL modu 'flexible' (uçtan uca şifreli değil)", severity: "P2", provider: "Cloudflare",
    pattern: /\bssl\s*=\s*"flexible"|value\s*=\s*"flexible"/,
    impact: "Flexible SSL origin'e düz HTTP gider; MITM riski.", recommendation: "SSL modunu 'full (strict)' yap.",
  },
  {
    id: "CLOUD-GCP-bucket-public", check: "CLOUD-GCP", title: "GCS bucket public (allUsers/allAuthenticatedUsers)", severity: "P0", provider: "GCP",
    pattern: /"(allUsers|allAuthenticatedUsers)"/,
    impact: "allUsers binding bucket'ı tüm internete açar; veri sızıntısı.", recommendation: "allUsers/allAuthenticatedUsers binding'lerini kaldır; uniform bucket-level access + IAM.",
  },
  {
    id: "CLOUD-GCP-sql-public", check: "CLOUD-GCP", title: "Cloud SQL public IP / 0.0.0.0/0 yetkili ağ", severity: "P1", provider: "GCP",
    pattern: /ipv4_enabled\s*=\s*true|authorized_networks[\s\S]*?"0\.0\.0\.0\/0"/,
    impact: "Cloud SQL public IP/0.0.0.0/0 ile internetten erişilebilir.", recommendation: "Private IP kullan; yetkili ağı daralt.",
  },
  {
    id: "CLOUD-GCP-fw-open", check: "CLOUD-GCP", title: "GCP firewall dünyaya açık (source_ranges 0.0.0.0/0)", severity: "P1", provider: "GCP",
    pattern: /source_ranges\s*=\s*\[\s*"0\.0\.0\.0\/0"/,
    impact: "0.0.0.0/0 firewall kuralı servisi tüm internete açar.", recommendation: "source_ranges'i bilinen IP'lere daralt.",
  },
];

const IAC_FILE = /\.(tf|tf\.json|hcl)$/i;
const SKIP = /(^|\/)(node_modules|dist|build|warden-report|vendor|\.terraform)\//;

export function analyzeCloud(files: ReadonlyArray<{ path: string; content: string }>): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const { path, content } of files) {
    const lines = content.split(/\r?\n/);
    for (const rule of RULES) {
      let hits = 0;
      for (let i = 0; i < lines.length && hits < 5; i++) {
        const ln = lines[i] as string;
        rule.pattern.lastIndex = 0;
        if (!rule.pattern.test(ln)) continue;
        hits++;
        const f = makeFinding({
          id: `${rule.id}:${path}:${i + 1}`,
          title: `${rule.title} (${rule.provider})`,
          severity: rule.severity, module: "CLOUD", check: rule.check, category: `Cloud / ${rule.provider}`,
          confidence: "medium",
          evidence: [{ type: "config", source: path, location: String(i + 1), excerpt: ln.trim().slice(0, 160) }],
          impact: rule.impact, recommendation: rule.recommendation, effort: "M", autoFixable: false,
          references: ["CIS Cloud Benchmark"],
        });
        if (seen.has(f.fingerprint)) continue;
        seen.add(f.fingerprint);
        findings.push(f);
      }
    }
  }
  return findings;
}

export function collectIacFiles(ctx: DetectContext): Array<{ path: string; content: string }> {
  const files = ctx.find((p) => IAC_FILE.test(p) && !SKIP.test(p), { limit: 1000 });
  const out: Array<{ path: string; content: string }> = [];
  for (const f of files) {
    const content = ctx.readFile(f);
    if (content !== null) out.push({ path: f, content });
  }
  return out;
}

export const cloudModule: WardenModule = {
  id: "CLOUD",
  title: "Cloud / IaC Güvenliği",
  active: false,
  applicable(ctx: ScanContext) {
    return collectIacFiles(ctx.fs).length > 0;
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const files = collectIacFiles(ctx.fs);
    const findings = analyzeCloud(files);
    ctx.audit.info(`CLOUD: ${files.length} IaC dosyası, ${findings.length} bulgu.`);
    return { findings };
  },
};

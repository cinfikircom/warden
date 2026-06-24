import type { Finding } from "../../model/finding.ts";
import type { Severity } from "../../model/severity.ts";
import { makeFinding } from "../../util/finding.ts";
import type { ProbeResponse } from "./client.ts";

/**
 * C1 — açıkta kalan hassas dosya probe'u. SPA'lar her yola 200 dönebildiği için her yolun
 * içerik DOĞRULAYICISI vardır (yalnızca gerçekten o dosyaya benziyorsa bulgu üretilir).
 */
export interface ExposedPath {
  readonly path: string;
  readonly severity: Severity;
  readonly title: string;
  /** Gövde gerçekten bu hassas dosya mı (HTML 404/SPA değil). */
  validate(body: string, contentType: string): boolean;
}

const notHtml = (ct: string): boolean => !ct.includes("text/html");

export const EXPOSED_PATHS: readonly ExposedPath[] = [
  { path: "/.env", severity: "P0", title: "Açıkta .env dosyası",
    validate: (b, ct) => notHtml(ct) && /^[A-Z0-9_]+\s*=/m.test(b) },
  { path: "/.git/config", severity: "P0", title: "Açıkta .git/config",
    validate: (b) => /\[core\]|\[remote /.test(b) },
  { path: "/.git/HEAD", severity: "P0", title: "Açıkta .git deposu (/.git/HEAD)",
    validate: (b) => /^ref:\s+refs\//.test(b.trim()) },
  { path: "/.aws/credentials", severity: "P0", title: "Açıkta AWS credentials",
    validate: (b) => /aws_access_key_id/i.test(b) },
  { path: "/.terraform.tfstate", severity: "P0", title: "Açıkta Terraform state",
    validate: (b) => /"terraform_version"|"resources"/.test(b) },
  { path: "/backup.sql", severity: "P0", title: "Açıkta SQL yedeği",
    validate: (b, ct) => notHtml(ct) && /(CREATE TABLE|INSERT INTO|DROP TABLE)/i.test(b) },
  { path: "/.npmrc", severity: "P1", title: "Açıkta .npmrc (token sızıntısı)",
    validate: (b) => /_authToken|registry=/.test(b) },
  { path: "/swagger.json", severity: "P1", title: "Public Swagger/OpenAPI",
    validate: (b) => /"swagger"|"openapi"/.test(b) },
  { path: "/api-docs", severity: "P1", title: "Public API dokümantasyonu",
    validate: (b) => /"swagger"|"openapi"|swagger-ui/i.test(b) },
  { path: "/actuator/health", severity: "P1", title: "Açıkta Spring Actuator",
    validate: (b) => /"status"\s*:\s*"(UP|DOWN)"/.test(b) },
  { path: "/.DS_Store", severity: "P2", title: "Açıkta .DS_Store",
    validate: (b) => b.includes("Bud1") || b.charCodeAt(0) === 0 },
];

/** Tek bir probe yanıtını değerlendirir. */
export function analyzeExposedFile(def: ExposedPath, res: ProbeResponse): Finding | null {
  if (res.status !== 200) return null;
  const ct = res.headers["content-type"] ?? "";
  if (!def.validate(res.body, ct)) return null;
  return makeFinding({
    id: `C1-exposed:${def.path}`,
    title: def.title,
    severity: def.severity,
    module: "C",
    check: "C1",
    category: "Exposed Sensitive File",
    confidence: "high",
    evidence: [{ type: "endpoint", source: res.url, location: String(res.status), excerpt: res.body.slice(0, 120) }],
    impact: "Hassas dosya internetten erişilebilir; secret/şema/altyapı sızıntısı.",
    recommendation: `Bu yolu engelle (web sunucu kuralı/WAF); dosyayı public kökten çıkar; sızan secret'ları rotasyon yap.`,
    effort: "S",
    autoFixable: false,
    references: ["OWASP A05:2021"],
  });
}

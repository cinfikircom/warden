import { execFileSync } from "node:child_process";
import type { Finding } from "../model/finding.ts";
import type { Severity } from "../model/severity.ts";
import type { AuditLog } from "../audit/log.ts";
import { makeFinding } from "../util/finding.ts";

/**
 * OSV-Scanner (google/osv-scanner) JSON → Warden Finding. Çok-ekosistemli SCA: Node yanı sıra
 * Python/Go/PHP/.NET/Rust vb. için `npm audit`'ten çok daha geniş zafiyet veritabanı (OSV.dev).
 * `sast/dependency.ts` (npm audit) Node ile sınırlıyken bu adapter tüm stack'leri kapsar.
 *
 * Saf normalizasyon (`osvToFindings`) test edilebilir; runner (`runOsvScanner`) best-effort:
 * binary yoksa/başarısızsa boş döner (graceful).
 */

const CVE_RE = /CVE-\d{4}-\d{3,7}/gi;

/** OSV/CVSS metin severity → Warden severity. */
function mapSeverity(label: string): Severity {
  switch (label.toUpperCase()) {
    case "CRITICAL":
      return "P0";
    case "HIGH":
      return "P1";
    case "MODERATE":
    case "MEDIUM":
      return "P2";
    default:
      return "P3";
  }
}

/** CVSS 3.1/4.0 taban skorundan severity. */
function scoreToSeverity(score: number): Severity {
  if (score >= 9.0) return "P0";
  if (score >= 7.0) return "P1";
  if (score >= 4.0) return "P2";
  return "P3";
}

function asObj(x: unknown): Record<string, unknown> | null {
  return x && typeof x === "object" ? (x as Record<string, unknown>) : null;
}

/** OSV-Scanner JSON metnini Finding[] listesine çevirir. Bozuk girdide [] (asla fırlatmaz). */
export function osvToFindings(jsonText: string): Finding[] {
  let doc: unknown;
  try {
    doc = JSON.parse(jsonText);
  } catch {
    return [];
  }
  const root = asObj(doc);
  if (!root) return [];
  const results = Array.isArray(root["results"]) ? (root["results"] as unknown[]) : [];
  const out: Finding[] = [];

  for (const rRaw of results) {
    const r = asObj(rRaw);
    if (!r) continue;
    const sourcePath = String(asObj(r["source"])?.["path"] ?? "manifest");
    const packages = Array.isArray(r["packages"]) ? (r["packages"] as unknown[]) : [];
    for (const pRaw of packages) {
      const p = asObj(pRaw);
      if (!p) continue;
      const pkg = asObj(p["package"]);
      const name = String(pkg?.["name"] ?? "?");
      const version = String(pkg?.["version"] ?? "");
      const ecosystem = String(pkg?.["ecosystem"] ?? "");
      const vulns = Array.isArray(p["vulnerabilities"]) ? (p["vulnerabilities"] as unknown[]) : [];
      for (const vRaw of vulns) {
        const v = asObj(vRaw);
        if (!v) continue;
        const id = String(v["id"] ?? "OSV");
        const summary = String(v["summary"] ?? v["details"] ?? `${name} zafiyeti`);
        const aliases = Array.isArray(v["aliases"]) ? (v["aliases"] as unknown[]).map(String) : [];
        const cves = [...new Set([...aliases, id].flatMap((s) => s.match(CVE_RE) ?? []).map((c) => c.toUpperCase()))];

        // Severity: CVSS skoru > database_specific.severity > "P2".
        let severity: Severity = "P2";
        const sevArr = Array.isArray(v["severity"]) ? (v["severity"] as unknown[]) : [];
        const cvss = sevArr.map(asObj).find((s) => s && String(s["type"]).startsWith("CVSS"));
        const dbSev = asObj(v["database_specific"])?.["severity"];
        if (cvss && cvss["score"] !== undefined) {
          const num = Number(cvss["score"]);
          if (!Number.isNaN(num)) severity = scoreToSeverity(num);
        } else if (dbSev !== undefined) {
          severity = mapSeverity(String(dbSev));
        }

        out.push(
          makeFinding({
            id: `B2-osv:${name}:${id}`,
            title: `Zafiyetli bağımlılık: ${name} (${id})`,
            severity,
            module: "B",
            check: "B2",
            category: "Vulnerable Component",
            confidence: "high",
            evidence: [
              {
                type: "command",
                source: `osv-scanner · ${sourcePath}`,
                excerpt: `${name}@${version}${ecosystem ? ` [${ecosystem}]` : ""}: ${summary}`.slice(0, 200),
              },
            ],
            impact: "Bilinen zafiyetli paket (OSV.dev); sömürülebilir açık üretim ortamına taşınır.",
            recommendation: `${name} paketini güvenli sürüme yükselt; ${id} danışma kaydına bak.`,
            effort: "S",
            autoFixable: true,
            references: ["OWASP A06:2021", "OSV", id, ...cves],
            ...(cves.length ? { cves } : {}),
          }),
        );
      }
    }
  }
  return out;
}

/** Best-effort: `osv-scanner` kuruluysa çalıştırıp bulgu üretir; yoksa boş (graceful). */
export function runOsvScanner(root: string, audit?: AuditLog): { findings: Finding[]; ran: boolean } {
  try {
    audit?.command("osv-scanner --format json --recursive .", root);
    const out = execFileSync("osv-scanner", ["--format", "json", "--recursive", "."], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 120_000,
      maxBuffer: 16_000_000,
    });
    return { findings: osvToFindings(out), ran: true };
  } catch (err) {
    // osv-scanner zafiyet bulunca non-zero çıkar ama JSON'u stdout'a yazar.
    const e = err as { stdout?: string | Buffer; code?: string };
    if (e?.stdout) {
      const text = typeof e.stdout === "string" ? e.stdout : e.stdout.toString("utf8");
      const f = osvToFindings(text);
      if (f.length > 0) return { findings: f, ran: true };
    }
    audit?.info("osv-scanner bulunamadı/çalışmadı — çok-ekosistem SCA atlandı (opsiyonel).");
    return { findings: [], ran: false };
  }
}

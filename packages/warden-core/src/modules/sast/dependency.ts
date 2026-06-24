import { execFileSync } from "node:child_process";
import type { Finding } from "../../model/finding.ts";
import type { Severity } from "../../model/severity.ts";
import type { DetectContext } from "../../detect/types.ts";
import type { AuditLog } from "../../audit/log.ts";
import { makeFinding } from "../../util/finding.ts";

/** npm/pnpm audit şiddetini Warden şiddetine eşler. */
const SEV_MAP: Record<string, Severity> = {
  critical: "P0",
  high: "P1",
  moderate: "P2",
  low: "P3",
  info: "P3",
};

export interface VulnPkg {
  readonly name: string;
  readonly severity: string;
  readonly title: string;
  readonly range?: string;
}

/**
 * Hem npm v7+ (`vulnerabilities`) hem v6/pnpm (`advisories`) audit JSON şekillerini ayrıştırır.
 * Saf fonksiyon — test edilebilir, ağ gerektirmez.
 */
export function parseAudit(jsonText: string): VulnPkg[] {
  let doc: unknown;
  try {
    doc = JSON.parse(jsonText);
  } catch {
    return [];
  }
  if (!doc || typeof doc !== "object") return [];
  const o = doc as Record<string, unknown>;
  const out: VulnPkg[] = [];

  // npm v7+: { vulnerabilities: { name: { severity, via:[{title}|str], range } } }
  const vulns = o["vulnerabilities"];
  if (vulns && typeof vulns === "object") {
    for (const [name, v] of Object.entries(vulns as Record<string, unknown>)) {
      if (!v || typeof v !== "object") continue;
      const vv = v as Record<string, unknown>;
      const severity = String(vv["severity"] ?? "low");
      let title = "";
      const via = vv["via"];
      if (Array.isArray(via)) {
        const first = via.find((x) => x && typeof x === "object");
        if (first) title = String((first as Record<string, unknown>)["title"] ?? "");
      }
      out.push({ name, severity, title: title || `${name} zafiyeti`, ...(vv["range"] ? { range: String(vv["range"]) } : {}) });
    }
    return out;
  }

  // v6/pnpm: { advisories: { id: { module_name, severity, title, vulnerable_versions } } }
  const adv = o["advisories"];
  if (adv && typeof adv === "object") {
    for (const a of Object.values(adv as Record<string, unknown>)) {
      if (!a || typeof a !== "object") continue;
      const aa = a as Record<string, unknown>;
      out.push({
        name: String(aa["module_name"] ?? "?"),
        severity: String(aa["severity"] ?? "low"),
        title: String(aa["title"] ?? "zafiyet"),
        ...(aa["vulnerable_versions"] ? { range: String(aa["vulnerable_versions"]) } : {}),
      });
    }
  }
  return out;
}

/** Zafiyet paketlerini bulgulara çevirir (saf). */
export function vulnsToFindings(vulns: readonly VulnPkg[]): Finding[] {
  return vulns.map((v) =>
    makeFinding({
      id: `B2-vuln:${v.name}`,
      title: `Zafiyetli bağımlılık: ${v.name} (${v.severity})`,
      severity: SEV_MAP[v.severity.toLowerCase()] ?? "P2",
      module: "B",
      check: "B2",
      category: "Vulnerable Component",
      confidence: "high",
      evidence: [{ type: "command", source: "npm/pnpm audit", excerpt: `${v.name}${v.range ? ` ${v.range}` : ""}: ${v.title}`.slice(0, 200) }],
      impact: "Bilinen CVE'li paket; sömürülebilir zafiyet üretim ortamına taşınır.",
      recommendation: `Paketi güncelle/değiştir (audit fix); ${v.range ?? "güvenli sürüm"} dışına çık.`,
      effort: "S",
      autoFixable: true,
      references: ["OWASP A06:2021", "OSV", "Trivy"],
    }),
  );
}

/**
 * Best-effort canlı audit (ağ gerektirir). Lockfile yoksa veya komut başarısızsa boş döner.
 * Read-only: yalnızca audit çalıştırır, fix UYGULAMAZ.
 */
export function collectAuditFindings(root: string, ctx: DetectContext, audit?: AuditLog): { findings: Finding[]; ran: boolean } {
  const hasPnpm = ctx.exists("pnpm-lock.yaml");
  const hasNpm = ctx.exists("package-lock.json");
  if (!hasPnpm && !hasNpm) return { findings: [], ran: false };

  const cmd = hasPnpm ? "pnpm" : "npm";
  try {
    audit?.command(`${cmd} audit --json`, root);
    const out = execFileSync(cmd, ["audit", "--json"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 60_000,
    });
    return { findings: vulnsToFindings(parseAudit(out)), ran: true };
  } catch (err: unknown) {
    // audit, zafiyet bulunca non-zero çıkar AMA JSON'u yine stdout'a yazar.
    const e = err as { stdout?: string | Buffer };
    if (e?.stdout) {
      const text = typeof e.stdout === "string" ? e.stdout : e.stdout.toString("utf8");
      const parsed = parseAudit(text);
      if (parsed.length > 0) return { findings: vulnsToFindings(parsed), ran: true };
    }
    audit?.warn(`${cmd} audit çalıştırılamadı (ağ/erişim?) — B2 atlandı.`);
    return { findings: [], ran: false };
  }
}

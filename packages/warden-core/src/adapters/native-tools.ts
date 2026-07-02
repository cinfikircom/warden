import { execFileSync } from "node:child_process";
import type { Finding, ModuleId } from "../model/finding.ts";
import type { Severity } from "../model/severity.ts";
import type { AuditLog } from "../audit/log.ts";
import { sarifToFindings } from "./sarif.ts";
import { makeFinding } from "../util/finding.ts";
import { maskSecrets } from "../secret/mask.ts";

/**
 * Native dış-araç runner'ları. Kuruluysa en-iyi motorları (OpenGrep/Semgrep, Trivy, Gitleaks,
 * Checkov, Nuclei) doğrudan çalıştırır ve SARIF/JSONL çıktısını Warden Finding'e normalize eder;
 * kurulu değilse GRACEFULLY atlar. Non-intrusive: yalnızca `WARDEN_TOOLS` ile açıkça istenenler
 * koşar. Aktif (DAST) araçlar (nuclei) yalnızca yetki kapısı açıkken.
 *
 * WARDEN_TOOLS=all  → tüm pasif araçlar   ·   WARDEN_TOOLS=opengrep,gitleaks → seçili
 */

export interface NativeToolSpec {
  readonly id: string;
  readonly bin: string;
  readonly title: string;
  /** Aktif/DAST mı — yalnızca yetki kapısı açıkken koşar. */
  readonly active?: boolean;
  /** Çalıştırma argümanları. */
  readonly args: (ctx: NativeToolContext) => string[];
  /** stdout → Finding[]. */
  readonly parse: (stdout: string) => Finding[];
}

export interface NativeToolContext {
  readonly root: string;
  /** DAST araçları için yetkili hedefler (allow-list). */
  readonly targets?: readonly string[];
}

/** Nuclei JSONL (satır başına bir JSON bulgu) → Finding. Saf. */
export function nucleiJsonlToFindings(stdout: string): Finding[] {
  const out: Finding[] = [];
  const SEV: Record<string, Severity> = { critical: "P0", high: "P1", medium: "P2", low: "P3", info: "P3", unknown: "P3" };
  for (const line of stdout.split(/\r?\n/)) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    let o: Record<string, unknown>;
    try {
      o = JSON.parse(t) as Record<string, unknown>;
    } catch {
      continue;
    }
    const info = (o["info"] ?? {}) as Record<string, unknown>;
    const sev = String(info["severity"] ?? "info").toLowerCase();
    const name = String(info["name"] ?? o["template-id"] ?? "nuclei finding");
    const matched = String(o["matched-at"] ?? o["host"] ?? "");
    out.push(
      makeFinding({
        id: `EXT-nuclei-${String(o["template-id"] ?? "t")}:${matched}`.slice(0, 90),
        title: `[nuclei] ${name}`,
        severity: SEV[sev] ?? "P3",
        module: "C",
        check: String(o["template-id"] ?? "nuclei"),
        category: "External · nuclei (DAST)",
        confidence: "medium",
        evidence: [{ type: "endpoint", source: matched || "target", excerpt: maskSecrets(name.slice(0, 200)) }],
        impact: `nuclei template eşleşti: ${name}`,
        recommendation: "İlgili nuclei template'inin açıklamasına göre düzelt/sertleştir.",
        effort: "M",
        autoFixable: false,
        references: ["nuclei", ...(Array.isArray(info["reference"]) ? (info["reference"] as unknown[]).map(String) : [])],
      }),
    );
  }
  return out;
}

/** Pasif native araçlar (SAST/SCA/secret/IaC). Hepsi SARIF üretir. */
export const PASSIVE_TOOLS: readonly NativeToolSpec[] = [
  {
    id: "opengrep",
    bin: "opengrep",
    title: "OpenGrep (SAST, taint)",
    args: () => ["--sarif", "--quiet", "--config", "auto", "."],
    parse: (out) => sarifToFindings(out, { module: "B" }),
  },
  {
    id: "semgrep",
    bin: "semgrep",
    title: "Semgrep CE (SAST)",
    args: () => ["--sarif", "--quiet", "--config", "auto", "."],
    parse: (out) => sarifToFindings(out, { module: "B" }),
  },
  {
    id: "trivy",
    bin: "trivy",
    title: "Trivy (SCA + IaC + secret)",
    args: () => ["fs", "--format", "sarif", "--quiet", "--scanners", "vuln,secret,misconfig", "."],
    parse: (out) => sarifToFindings(out, { sourceLabel: "trivy" }),
  },
  {
    id: "gitleaks",
    bin: "gitleaks",
    title: "Gitleaks (secret)",
    // gitleaks ≥8.19: `detect` kaldırıldı → `dir` (çalışma ağacı) / `git` (geçmiş). stdout: -r -
    args: () => ["dir", ".", "--report-format", "sarif", "--report-path", "-", "--no-banner", "--redact"],
    parse: (out) => sarifToFindings(out, { module: "B" }),
  },
  {
    id: "checkov",
    bin: "checkov",
    title: "Checkov (IaC misconfig)",
    args: () => ["-d", ".", "-o", "sarif", "--compact", "--quiet"],
    parse: (out) => sarifToFindings(out, { module: "CLOUD" }),
  },
];

/** Aktif (DAST) native araçlar — yetki kapılı. */
export const ACTIVE_TOOLS: readonly NativeToolSpec[] = [
  {
    id: "nuclei",
    bin: "nuclei",
    title: "Nuclei (DAST templates)",
    active: true,
    args: (ctx) => [
      ...(ctx.targets ?? []).flatMap((t) => ["-target", t]),
      "-jsonl",
      "-silent",
      "-severity",
      "low,medium,high,critical",
      // Non-destructive: yalnızca güvenli template etiketleri; müdahaleci/DoS template'leri hariç.
      "-exclude-tags",
      "dos,fuzz,intrusive,brute-force",
    ],
    parse: nucleiJsonlToFindings,
  },
];

/** WARDEN_TOOLS ortam değişkenini ayrıştırır. */
export function enabledTools(env: Record<string, string | undefined> = process.env): "all" | Set<string> {
  const raw = (env["WARDEN_TOOLS"] ?? "").trim().toLowerCase();
  if (!raw) return new Set<string>();
  if (raw === "all") return "all";
  return new Set(raw.split(",").map((s) => s.trim()).filter(Boolean));
}

function isEnabled(spec: NativeToolSpec, enabled: "all" | Set<string>): boolean {
  if (enabled === "all") return !spec.active; // "all" yalnızca pasif araçları kapsar (aktif=explicit)
  return enabled.has(spec.id);
}

/** Tek bir native aracı best-effort çalıştırır. Binary yoksa/hata olursa graceful boş döner. */
export function runNativeTool(spec: NativeToolSpec, ctx: NativeToolContext, audit?: AuditLog): { findings: Finding[]; ran: boolean } {
  try {
    const args = spec.args(ctx);
    audit?.command(`${spec.bin} ${args.join(" ")}`, ctx.root);
    const out = execFileSync(spec.bin, args, {
      cwd: ctx.root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 180_000,
      maxBuffer: 32_000_000,
    });
    return { findings: spec.parse(out), ran: true };
  } catch (err) {
    // Araç bulgu bulunca non-zero çıkabilir ama SARIF/JSONL'i stdout'a yazar.
    const e = err as { stdout?: string | Buffer; code?: string };
    if (e?.stdout) {
      const text = typeof e.stdout === "string" ? e.stdout : e.stdout.toString("utf8");
      const parsed = spec.parse(text);
      if (parsed.length > 0) return { findings: parsed, ran: true };
    }
    if (e?.code === "ENOENT") audit?.info(`${spec.id} kurulu değil — atlandı (opsiyonel).`);
    else audit?.info(`${spec.id} çalıştırılamadı — atlandı.`);
    return { findings: [], ran: false };
  }
}

/** İstenen (WARDEN_TOOLS) pasif native araçları çalıştırır. */
export function runPassiveTools(root: string, audit?: AuditLog): Finding[] {
  const enabled = enabledTools();
  const out: Finding[] = [];
  for (const spec of PASSIVE_TOOLS) {
    if (!isEnabled(spec, enabled)) continue;
    const res = runNativeTool(spec, { root }, audit);
    if (res.ran) {
      audit?.info(`${spec.title}: ${res.findings.length} bulgu.`);
      out.push(...res.findings);
    }
  }
  return out;
}

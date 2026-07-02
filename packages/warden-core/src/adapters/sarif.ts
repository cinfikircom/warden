import type { Finding, ModuleId } from "../model/finding.ts";
import type { Severity } from "../model/severity.ts";
import { makeFinding } from "../util/finding.ts";
import { maskSecrets } from "../secret/mask.ts";

/**
 * Genel SARIF 2.1.0 → Warden Finding normalizasyonu (orkestratör katmanı).
 *
 * Warden'ın asıl kaldıracı: kural kalitesinde en-iyi motorlarla (OpenGrep/Semgrep, Trivy,
 * Gitleaks, Checkov, Nuclei — hepsi SARIF üretir) yarışmak yerine onların çıktısını sarıp
 * kendi ayırt edici katmanını (fingerprint/delta, skorlama, playbook, waiver, SARIF re-export)
 * üzerine koymak. Bu saf fonksiyon her SARIF üreten aracı Warden'a bağlar.
 *
 * Bulgular araç-türüne göre modüle atanır (IaC→CLOUD, K8s→K8S, DAST→C, SAST/secret/SCA→B);
 * `opts.module` verilirse o kazanır.
 */

const SANITIZE = /[^A-Za-z0-9._-]+/g;

/** Araç adından Warden modülü çıkarır (scoreboard boyutu). Bilinmiyorsa "B" (SAST). */
export function inferModule(toolName: string): ModuleId {
  const t = toolName.toLowerCase();
  if (/checkov|tfsec|kics|terrascan|cloudsploit|prowler/.test(t)) return "CLOUD";
  if (/kubescape|kube-bench|kubeaudit|polaris/.test(t)) return "K8S";
  if (/nuclei|zap|nikto|wapiti|arachni/.test(t)) return "C";
  return "B"; // semgrep/opengrep/gitleaks/trufflehog/bandit/gosec/trivy/grype/snyk...
}
const CVE_RE = /CVE-\d{4}-\d{3,7}/gi;

/** SARIF `level` → Warden severity (security-severity yoksa). */
function levelToSeverity(level: string | undefined): Severity {
  switch ((level ?? "warning").toLowerCase()) {
    case "error":
      return "P1";
    case "warning":
      return "P2";
    default:
      return "P3"; // note / none
  }
}

/** SARIF `security-severity` (0–10, CVSS benzeri) → Warden severity. */
function severityFromScore(score: number): Severity {
  if (score >= 9.0) return "P0";
  if (score >= 7.0) return "P1";
  if (score >= 4.0) return "P2";
  return "P3";
}

function asObj(x: unknown): Record<string, unknown> | null {
  return x && typeof x === "object" ? (x as Record<string, unknown>) : null;
}

function extractCves(text: string): string[] {
  const m = text.match(CVE_RE);
  if (!m) return [];
  return [...new Set(m.map((c) => c.toUpperCase()))];
}

export interface SarifImportOptions {
  /** Bulguların atanacağı modül (varsayılan "B"). */
  readonly module?: ModuleId;
  /** Kaynak etiketi (rapor/kanıtta görünür). Verilmezse SARIF tool adı. */
  readonly sourceLabel?: string;
}

/** SARIF metnini Finding[] listesine çevirir. Bozuk/boş girdide [] döner (asla fırlatmaz). */
export function sarifToFindings(jsonText: string, opts: SarifImportOptions = {}): Finding[] {
  let doc: unknown;
  try {
    doc = JSON.parse(jsonText);
  } catch {
    return [];
  }
  const root = asObj(doc);
  if (!root) return [];
  const runs = Array.isArray(root["runs"]) ? (root["runs"] as unknown[]) : [];
  const out: Finding[] = [];

  for (const runRaw of runs) {
    const run = asObj(runRaw);
    if (!run) continue;
    const driver = asObj(asObj(run["tool"])?.["driver"]);
    const toolName = String(driver?.["name"] ?? "external");
    const label = opts.sourceLabel ?? toolName;
    const module = opts.module ?? inferModule(toolName);

    // Kural indeksi: id + properties (security-severity, tags, help).
    const rulesArr = Array.isArray(driver?.["rules"]) ? (driver!["rules"] as unknown[]) : [];
    const ruleById = new Map<string, Record<string, unknown>>();
    const ruleByIndex: Array<Record<string, unknown>> = [];
    for (const r of rulesArr) {
      const ro = asObj(r);
      if (!ro) continue;
      ruleByIndex.push(ro);
      if (ro["id"]) ruleById.set(String(ro["id"]), ro);
    }

    const results = Array.isArray(run["results"]) ? (run["results"] as unknown[]) : [];
    for (const resRaw of results) {
      const res = asObj(resRaw);
      if (!res) continue;

      const ruleId = String(res["ruleId"] ?? (asObj(res["rule"])?.["id"] as string | undefined) ?? "rule");
      const ruleIdx = typeof res["ruleIndex"] === "number" ? (res["ruleIndex"] as number) : -1;
      const rule = ruleById.get(ruleId) ?? (ruleIdx >= 0 ? ruleByIndex[ruleIdx] : undefined);

      const message = String(asObj(res["message"])?.["text"] ?? ruleId);

      // Konum.
      const loc = Array.isArray(res["locations"]) ? asObj((res["locations"] as unknown[])[0]) : null;
      const phys = asObj(loc?.["physicalLocation"]);
      const uri = String(asObj(phys?.["artifactLocation"])?.["uri"] ?? "");
      const startLine = asObj(phys?.["region"])?.["startLine"];
      const location = startLine !== undefined ? String(startLine) : undefined;

      // Severity: security-severity (result.properties → rule.properties) > level.
      const resProps = asObj(res["properties"]);
      const ruleProps = asObj(rule?.["properties"]);
      const secSevRaw =
        resProps?.["security-severity"] ?? ruleProps?.["security-severity"];
      let severity: Severity;
      const secSev = secSevRaw !== undefined ? Number(secSevRaw) : NaN;
      if (!Number.isNaN(secSev)) severity = severityFromScore(secSev);
      else severity = levelToSeverity(res["level"] as string | undefined);

      // Referanslar: araç adı + rule tags + CWE/OWASP.
      const tags = Array.isArray(ruleProps?.["tags"]) ? (ruleProps!["tags"] as unknown[]).map(String) : [];
      const references = [label, ...tags].filter(Boolean);
      const cves = extractCves(`${ruleId} ${message}`);

      const idBase = `EXT-${toolName}-${ruleId}`.replace(SANITIZE, "-").slice(0, 80);
      out.push(
        makeFinding({
          id: `${idBase}:${uri || "n-a"}:${location ?? "0"}`,
          title: `[${toolName}] ${ruleId}`,
          severity,
          module,
          check: ruleId.replace(SANITIZE, "-").slice(0, 40) || "EXT",
          category: `External · ${toolName}`,
          confidence: "medium",
          evidence: [
            {
              type: uri ? "file" : "command",
              source: uri || label,
              ...(location ? { location } : {}),
              excerpt: maskSecrets(message.slice(0, 200)),
            },
          ],
          impact: `${toolName} tarafından raporlandı: ${message.slice(0, 160)}`,
          recommendation: `Aracın (${toolName}) önerdiği düzeltmeyi uygula; ${ruleId} kuralına bak.`,
          effort: "M",
          autoFixable: false,
          references,
          ...(cves.length ? { cves } : {}),
        }),
      );
    }
  }
  return out;
}

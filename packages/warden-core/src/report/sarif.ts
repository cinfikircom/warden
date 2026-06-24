import type { Finding } from "../model/finding.ts";
import type { Severity } from "../model/severity.ts";
import { maskSecrets } from "../secret/mask.ts";

/**
 * SARIF 2.1.0 dışa aktarımı (nokta 3). GitHub Code Scanning, Azure DevOps ve diğerleri
 * SARIF tüketir. Finding modeli baştan buna uyumlu tasarlandı; sonradan dönüştürme zorluğu yok.
 */

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  P0: "error",
  P1: "error",
  P2: "warning",
  P3: "note",
};

/** Şiddeti SARIF security-severity (0–10) puanına çevirir. CVSS varsa onu kullanır. */
function securitySeverity(f: Finding): string {
  if (typeof f.cvss === "number") return f.cvss.toFixed(1);
  const map: Record<Severity, number> = { P0: 9.0, P1: 7.0, P2: 4.0, P3: 1.0 };
  return map[f.severity].toFixed(1);
}

function fileEvidence(f: Finding): Array<{ uri: string; startLine?: number }> {
  return f.evidence
    .filter((e) => e.type === "file")
    .map((e) => {
      const line = e.location ? Number.parseInt(e.location, 10) : Number.NaN;
      return Number.isFinite(line) ? { uri: e.source, startLine: line } : { uri: e.source };
    });
}

export function toSarif(findings: readonly Finding[], wardenVersion: string): string {
  // Kurallar: benzersiz check başına bir rule.
  const ruleMap = new Map<string, Finding>();
  for (const f of findings) if (!ruleMap.has(f.check)) ruleMap.set(f.check, f);

  const rules = [...ruleMap.values()].map((f) => ({
    id: f.check,
    name: `${f.module}-${f.check}`,
    shortDescription: { text: f.category },
    fullDescription: { text: maskSecrets(f.impact) },
    defaultConfiguration: { level: LEVEL[f.severity] },
    properties: { tags: [f.module, ...(f.references ?? [])] },
  }));

  const results = findings.map((f) => {
    const locs = fileEvidence(f);
    return {
      ruleId: f.check,
      level: LEVEL[f.severity],
      message: { text: `[${f.severity}] ${maskSecrets(f.title)} — ${maskSecrets(f.recommendation)}` },
      partialFingerprints: { wardenFingerprint: f.fingerprint },
      properties: {
        severity: f.severity,
        "security-severity": securitySeverity(f),
        confidence: f.confidence,
        findingId: f.id,
        effort: f.effort,
        autoFixable: f.autoFixable,
      },
      locations:
        locs.length > 0
          ? locs.map((l) => ({
              physicalLocation: {
                artifactLocation: { uri: l.uri },
                ...(l.startLine ? { region: { startLine: l.startLine } } : {}),
              },
            }))
          : [
              {
                physicalLocation: { artifactLocation: { uri: f.evidence[0]?.source ?? "unknown" } },
              },
            ],
    };
  });

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Warden",
            version: wardenVersion,
            informationUri: "https://github.com/warden",
            rules,
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

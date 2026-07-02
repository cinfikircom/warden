import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../model/finding.ts";

/**
 * KEV + EPSS önceliklendirme (CVSS'in ötesinde). Modern pratik: bir zafiyetin GERÇEK dünya
 * tehdidini ölç — CISA KEV (bilinen-sömürülen) ve EPSS (30 gün içinde sömürülme olasılığı).
 *
 * Pasif ilkeye sadık: AĞ İSTEĞİ YAPMAZ. Veriyi opsiyonel yerel anlık-görüntülerden okur:
 *   warden-data/kev.json  — CISA KEV (ham feed VEYA düz CVE listesi)
 *   warden-data/epss.json — { "CVE-...": 0.97, ... } VEYA FIRST EPSS API şekli
 * Dosya yoksa zenginleştirme sessizce atlanır (bulgular olduğu gibi kalır).
 */

const CVE_RE = /CVE-\d{4}-\d{3,7}/gi;

/** CISA KEV feed'ini veya düz listeyi CVE kümesine çevirir (saf). */
export function parseKev(jsonText: string): Set<string> {
  const set = new Set<string>();
  let doc: unknown;
  try {
    doc = JSON.parse(jsonText);
  } catch {
    return set;
  }
  const add = (s: unknown) => {
    const m = String(s).match(CVE_RE);
    if (m) for (const c of m) set.add(c.toUpperCase());
  };
  if (Array.isArray(doc)) {
    for (const x of doc) add(typeof x === "string" ? x : (x as Record<string, unknown>)?.["cveID"]);
  } else if (doc && typeof doc === "object") {
    const vulns = (doc as Record<string, unknown>)["vulnerabilities"];
    if (Array.isArray(vulns)) for (const v of vulns) add((v as Record<string, unknown>)?.["cveID"]);
  }
  return set;
}

/** EPSS anlık-görüntüsünü { CVE: skor } haritasına çevirir (saf). */
export function parseEpss(jsonText: string): Map<string, number> {
  const map = new Map<string, number>();
  let doc: unknown;
  try {
    doc = JSON.parse(jsonText);
  } catch {
    return map;
  }
  const put = (cve: unknown, score: unknown) => {
    const c = String(cve).toUpperCase();
    const s = Number(score);
    if (CVE_RE.test(c) && !Number.isNaN(s)) map.set(c, s);
    CVE_RE.lastIndex = 0;
  };
  if (Array.isArray(doc)) {
    // FIRST API: { data: [{ cve, epss }] } veya düz [{ cve, epss }]
    for (const x of doc) put((x as Record<string, unknown>)?.["cve"], (x as Record<string, unknown>)?.["epss"]);
  } else if (doc && typeof doc === "object") {
    const o = doc as Record<string, unknown>;
    if (Array.isArray(o["data"])) {
      for (const x of o["data"] as unknown[]) put((x as Record<string, unknown>)?.["cve"], (x as Record<string, unknown>)?.["epss"]);
    } else {
      for (const [k, val] of Object.entries(o)) put(k, val);
    }
  }
  return map;
}

/** Bir bulgunun ilişkili CVE'lerini toplar (cves alanı + referanslar + id + kanıt). */
export function cvesOfFinding(f: Finding): string[] {
  const hay = [
    ...(f.cves ?? []),
    ...(f.references ?? []),
    f.id,
    ...f.evidence.map((e) => `${e.source} ${e.excerpt ?? ""}`),
  ].join(" ");
  const m = hay.match(CVE_RE);
  return m ? [...new Set(m.map((c) => c.toUpperCase()))] : [];
}

/**
 * Bulgulara KEV/EPSS bağlamı ekler. KEV eşleşmesi → kev=true + exploitability "high" +
 * "CISA KEV" referansı. EPSS varsa en yüksek skor eklenir; yüksek EPSS de exploitability'yi
 * yükseltir. Severity DEĞİŞTİRİLMEZ (raporlama tutarlılığı) — yalnızca önceliklendirme sinyali.
 */
export function enrichKevEpss(
  findings: readonly Finding[],
  kev: ReadonlySet<string>,
  epss: ReadonlyMap<string, number>,
): Finding[] {
  if (kev.size === 0 && epss.size === 0) return [...findings];
  return findings.map((f) => {
    const cves = cvesOfFinding(f);
    if (cves.length === 0) return f;
    const isKev = cves.some((c) => kev.has(c));
    let epssScore: number | undefined;
    for (const c of cves) {
      const s = epss.get(c);
      if (s !== undefined) epssScore = Math.max(epssScore ?? 0, s);
    }
    if (!isKev && epssScore === undefined) return f;
    const escalate = isKev || (epssScore !== undefined && epssScore >= 0.5);
    const refs = new Set(f.references ?? []);
    if (isKev) refs.add("CISA KEV (aktif sömürülüyor)");
    if (epssScore !== undefined) refs.add(`EPSS ${(epssScore * 100).toFixed(1)}%`);
    return {
      ...f,
      ...(isKev ? { kev: true } : {}),
      ...(epssScore !== undefined ? { epss: epssScore } : {}),
      ...(escalate ? { exploitability: "high" as const } : {}),
      references: [...refs],
      cves: cves,
    };
  });
}

/** warden-data/ altındaki opsiyonel KEV/EPSS anlık-görüntülerini yükler (yoksa boş). */
export function loadKevData(root: string): { kev: Set<string>; epss: Map<string, number> } {
  const read = (name: string): string | null => {
    try {
      return readFileSync(join(root, "warden-data", name), "utf8");
    } catch {
      return null;
    }
  };
  const kevText = read("kev.json");
  const epssText = read("epss.json");
  return {
    kev: kevText ? parseKev(kevText) : new Set<string>(),
    epss: epssText ? parseEpss(epssText) : new Map<string, number>(),
  };
}

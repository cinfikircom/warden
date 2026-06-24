import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

type YamlValue = unknown;

/**
 * Yetki Kapısı (iş emri §2.2). Aktif/DAST testleri YALNIZCA proje kökünde geçerli bir
 * `warden.authz.yml` varsa VE zorunlu alanlar doluysa açılır. Aksi halde mod PASİF kalır.
 */

export type WardenMode = "passive" | "active";

export interface AuthzLimits {
  readonly maxRequestsPerSecond: number;
  readonly maxTotalRequests: number;
  readonly allowPortScan: boolean;
  readonly allowDefaultCredCheck: boolean;
}

export const DEFAULT_LIMITS: AuthzLimits = {
  maxRequestsPerSecond: 2,
  maxTotalRequests: 500,
  allowPortScan: false,
  allowDefaultCredCheck: true,
};

export interface AuthzResult {
  /** Etkin çalışma modu. Aktif testler yalnızca "active" iken çalışır. */
  readonly mode: WardenMode;
  /** Aktif test izinli olan tek host/domain/IP listesi (allow-list). */
  readonly authorizedTargets: readonly string[];
  readonly authorizedBy: string | null;
  readonly date: string | null;
  readonly limits: AuthzLimits;
  /** Kararın insan-okur gerekçeleri (audit log + rapora yazılır). */
  readonly reasons: readonly string[];
  /** Yetki dosyası diskte bulundu mu. */
  readonly fileFound: boolean;
}

function asString(v: YamlValue | undefined): string | null {
  return typeof v === "string" && v.trim() !== "" ? v.trim() : null;
}

function asStringList(v: YamlValue | undefined): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === "string" && x.trim() !== "").map((x) => x.trim());
}

function readLimits(v: YamlValue | undefined): AuthzLimits {
  if (v === null || v === undefined || Array.isArray(v) || typeof v !== "object") return DEFAULT_LIMITS;
  const o = v as Record<string, YamlValue>;
  const num = (key: string, def: number): number =>
    typeof o[key] === "number" && Number.isFinite(o[key]) ? (o[key] as number) : def;
  const bool = (key: string, def: boolean): boolean => (typeof o[key] === "boolean" ? (o[key] as boolean) : def);
  return {
    maxRequestsPerSecond: num("max_requests_per_second", DEFAULT_LIMITS.maxRequestsPerSecond),
    maxTotalRequests: num("max_total_requests", DEFAULT_LIMITS.maxTotalRequests),
    allowPortScan: bool("allow_port_scan", DEFAULT_LIMITS.allowPortScan),
    allowDefaultCredCheck: bool("allow_default_cred_check", DEFAULT_LIMITS.allowDefaultCredCheck),
  };
}

const passiveFallback = (reasons: string[], fileFound: boolean): AuthzResult => ({
  mode: "passive",
  authorizedTargets: [],
  authorizedBy: null,
  date: null,
  limits: DEFAULT_LIMITS,
  reasons,
  fileFound,
});

/**
 * Proje kökünden yetki dosyasını okur ve modu belirler.
 * Güvenli varsayılan: en ufak şüphe/eksiklikte PASİF.
 */
export function evaluateAuthz(projectRoot: string, fileName = "warden.authz.yml"): AuthzResult {
  const path = join(projectRoot, fileName);

  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return passiveFallback(
      [`Yetki dosyası yok (${fileName}). Mod: PASİF. Aktif test yapılmayacak.`],
      false,
    );
  }

  let doc: Record<string, YamlValue>;
  try {
    const parsed: unknown = parseYaml(text);
    doc = parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, YamlValue>)
      : {};
  } catch (err) {
    return passiveFallback(
      [`Yetki dosyası okunamadı (${String(err)}). Güvenli varsayılan: PASİF.`],
      true,
    );
  }

  const reasons: string[] = [];
  const attestation = doc["owner_attestation"] === true;
  const targets = asStringList(doc["authorized_targets"]);
  const authorizedBy = asString(doc["authorized_by"]);
  const date = asString(doc["date"]);
  const limits = readLimits(doc["limits"]);

  if (!attestation) reasons.push("owner_attestation true değil.");
  if (targets.length === 0) reasons.push("authorized_targets boş (allow-list yok).");
  if (!authorizedBy) reasons.push("authorized_by boş (denetim izi eksik).");
  if (!date) reasons.push("date boş (denetim izi eksik).");

  if (reasons.length > 0) {
    return {
      mode: "passive",
      authorizedTargets: targets,
      authorizedBy,
      date,
      limits,
      reasons: [`Yetki dosyası var ama eksik → Mod: PASİF. ${reasons.join(" ")}`],
      fileFound: true,
    };
  }

  return {
    mode: "active",
    authorizedTargets: targets,
    authorizedBy,
    date,
    limits,
    reasons: [
      `Yetki kapısı AÇIK → Mod: AKTİF. Yetkilendiren: ${authorizedBy} (${date}). ` +
        `Allow-list: ${targets.join(", ")}. Aktif testler yalnızca bu hedeflere, rate-limited.`,
    ],
    fileFound: true,
  };
}

/** Allow-list girdisini bare hostname'e indirger (şema/port/yol soyulur). */
function toHost(entry: string): string {
  let s = entry.toLowerCase().trim();
  if (s.includes("://")) {
    try {
      return new URL(s).hostname;
    } catch {
      /* düş */
    }
  }
  // host:port → host (IPv6 değilse)
  if (!s.includes("[") && s.split(":").length === 2) s = s.split(":")[0] as string;
  return s;
}

/** Bir hedefin allow-list'te olup olmadığını söyler (aktif test öncesi zorunlu kontrol). */
export function isTargetAuthorized(authz: AuthzResult, target: string): boolean {
  if (authz.mode !== "active") return false;
  const t = toHost(target);
  return authz.authorizedTargets.some((a) => {
    const al = toHost(a);
    return t === al || t.endsWith(`.${al}`) || t === `www.${al}`;
  });
}

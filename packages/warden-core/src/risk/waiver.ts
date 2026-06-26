import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import type { Finding } from "../model/finding.ts";

/**
 * Waiver (gerekçeli bastırma) — proje kökündeki `.warden-ignore.yml`.
 *
 * Burada listelenen bulgular RAPORDAN ve CI gate'inden (--fail-on) düşülür; ama
 * sessizce kaybolmazlar: her uygulanan waiver audit log'a ve CLI özetine yazılır.
 * Her girdi bir `reason` ister (denetim izi). Selector'lar AND mantığıyla eşleşir:
 * bir waiver'da hangi alanlar verilmişse hepsi tutmalıdır.
 *
 * Örnek:
 *   waivers:
 *     - fingerprint: "a1b2c3..."   # en kararlı; içerik özetine bağlanır
 *       reason: "Kendi kural tablomuz; gerçek CVV saklama değil."
 *     - check: "B3"                # daha geniş; tüm B3 bulguları
 *       reason: "SHA1 yalnızca fingerprint için, güvenlik amaçlı değil."
 *       expires: "2026-12-31"      # opsiyonel; geçmişse waiver pasif sayılır
 */

export const WAIVER_FILE = ".warden-ignore.yml";

export interface Waiver {
  /** Bulgunun içerik-türevli fingerprint'i (en kararlı selector). */
  readonly fingerprint?: string;
  /** Modül içi kontrol kodu, örn. "B3" (daha geniş eşleşme). */
  readonly check?: string;
  /** İnsan-okur stabil id, örn. "B3-weak-hash". */
  readonly id?: string;
  /** Zorunlu: neden bastırıldığı (denetim izi). */
  readonly reason: string;
  /** Opsiyonel son geçerlilik (YYYY-MM-DD). Geçmişse waiver uygulanmaz. */
  readonly expires?: string;
}

export interface WaiverLoad {
  readonly waivers: readonly Waiver[];
  /** Dosya bulundu mu (yoksa boş + fileFound=false). */
  readonly fileFound: boolean;
  /** Atlanan/bozuk girdiler için insan-okur uyarılar (audit log'a yazılır). */
  readonly warnings: readonly string[];
}

/** Bir bulguya uygulanmış waiver: hangi bulgu, hangi gerekçe. */
export interface AppliedWaiver {
  readonly finding: Finding;
  readonly reason: string;
}

export interface Partition {
  readonly active: readonly Finding[];
  readonly waived: readonly AppliedWaiver[];
}

function asString(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() !== "" ? v.trim() : undefined;
}

/** `.warden-ignore.yml`'i okur ve geçerli waiver girdilerini döndürür. Yoksa/bozuksa güvenli boş set. */
export function loadWaivers(projectRoot: string, fileName: string = WAIVER_FILE): WaiverLoad {
  const path = join(projectRoot, fileName);
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return { waivers: [], fileFound: false, warnings: [] };
  }

  let doc: unknown;
  try {
    doc = parseYaml(text);
  } catch (err) {
    return { waivers: [], fileFound: true, warnings: [`${fileName} okunamadı (${String(err)}); waiver uygulanmadı.`] };
  }

  const list =
    doc !== null && typeof doc === "object" && !Array.isArray(doc) && Array.isArray((doc as Record<string, unknown>).waivers)
      ? ((doc as Record<string, unknown>).waivers as unknown[])
      : [];

  const waivers: Waiver[] = [];
  const warnings: string[] = [];
  list.forEach((raw, i) => {
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      warnings.push(`${fileName} waiver #${i + 1}: nesne değil, atlandı.`);
      return;
    }
    const o = raw as Record<string, unknown>;
    const fingerprint = asString(o.fingerprint);
    const check = asString(o.check);
    const id = asString(o.id);
    const reason = asString(o.reason);
    const expires = asString(o.expires);
    if (!fingerprint && !check && !id) {
      warnings.push(`${fileName} waiver #${i + 1}: fingerprint/check/id yok, atlandı.`);
      return;
    }
    if (!reason) {
      warnings.push(`${fileName} waiver #${i + 1}: reason zorunlu, atlandı.`);
      return;
    }
    waivers.push({ ...(fingerprint && { fingerprint }), ...(check && { check }), ...(id && { id }), reason, ...(expires && { expires }) });
  });

  return { waivers, fileFound: true, warnings };
}

/** Waiver'ın bugün (nowIso, YYYY-MM-DD ön eki) geçerli olup olmadığı. expires yoksa hep geçerli. */
function isActive(w: Waiver, today: string): boolean {
  if (!w.expires) return true;
  return w.expires >= today; // YYYY-MM-DD leksikografik karşılaştırma = tarih karşılaştırması
}

/** Bir waiver'ın verilen bulguyu kapsayıp kapsamadığı (verilen tüm selector'lar AND ile tutmalı). */
function matches(w: Waiver, f: Finding): boolean {
  if (w.fingerprint && w.fingerprint !== f.fingerprint) return false;
  if (w.check && w.check !== f.check) return false;
  if (w.id && w.id !== f.id) return false;
  return true;
}

/**
 * Bulguları aktif / waived olarak ayırır. Süresi geçmiş waiver'lar yok sayılır.
 * @param nowIso ISO zaman damgası; tarih kısmı (YYYY-MM-DD) expires kıyaslaması için kullanılır.
 */
export function partitionWaived(
  findings: readonly Finding[],
  waivers: readonly Waiver[],
  nowIso: string,
): Partition {
  const today = nowIso.slice(0, 10);
  const live = waivers.filter((w) => isActive(w, today));
  const active: Finding[] = [];
  const waived: AppliedWaiver[] = [];
  for (const f of findings) {
    const hit = live.find((w) => matches(w, f));
    if (hit) waived.push({ finding: f, reason: hit.reason });
    else active.push(f);
  }
  return { active, waived };
}

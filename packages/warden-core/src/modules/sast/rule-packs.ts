import { parse } from "yaml";
import type { DetectContext } from "../../detect/types.ts";
import type { SourceRule } from "./scanner.ts";
import { MODULES } from "../../model/finding.ts";
import type { ModuleId, Confidence } from "../../model/finding.ts";
import { SEVERITIES } from "../../model/severity.ts";
import type { Severity } from "../../model/severity.ts";

/**
 * RULE PACKS — `warden-rules/*.yml` ile dışarıdan kural ekleme.
 *
 * Strix'ten devralınan üçüncü kalem: kapsamı kod değiştirmeden genişletme.
 *
 * ⛔ **GÜVENLİK KURALI: harici kural KOD ÇALIŞTIRAMAZ.**
 *
 * `SourceRule.validate` bir fonksiyondur ve YAML'dan gelemez. Gelebilseydi, bir kural
 * dosyası indirmek uzaktan kod çalıştırma yüzeyi olurdu — üstelik bir GÜVENLİK aracında,
 * yani en çok güvenilmesi gereken yerde. Yalnızca bildirimsel alanlar desteklenir ve
 * bilinmeyen alanlar sessizce yok sayılmaz, uyarı üretir.
 *
 * Regex kaynaklı ReDoS riski de ele alınır: desen uzunluğu sınırlıdır ve iç içe niceleyici
 * içeren desenler reddedilir (kendi B6-redos kuralımızın aradığı kalıp). Kendi motorunu
 * kilitleyebilen bir kural paketi kabul edilemez.
 *
 * Bkz. docs/STRIX-ADOPTION.md §1.4
 */

/** Kural paketlerinin arandığı dizin. */
export const RULE_PACK_DIR = "warden-rules";

/** Tek bir desenin en fazla uzunluğu — patolojik regex'lere karşı ucuz bir set. */
const MAX_PATTERN_LEN = 500;
/** İç içe niceleyici: `(a+)+` — catastrophic backtracking imzası. */
const NESTED_QUANTIFIER = /\((?!\?)[^()]*[+*]\)[+*]/;

export interface RulePackLoad {
  readonly rules: readonly SourceRule[];
  /** Yüklenemeyen/reddedilen girdiler. Sessiz atlama YOK — hepsi audit'e yazılır. */
  readonly warnings: readonly string[];
  /** Okunan paket dosyaları. */
  readonly files: readonly string[];
}

interface RawRule {
  id?: unknown;
  check?: unknown;
  module?: unknown;
  title?: unknown;
  severity?: unknown;
  category?: unknown;
  confidence?: unknown;
  pattern?: unknown;
  flags?: unknown;
  pathInclude?: unknown;
  pathExclude?: unknown;
  impact?: unknown;
  recommendation?: unknown;
  references?: unknown;
  effort?: unknown;
  maxPerFile?: unknown;
  taintAware?: unknown;
  requiresTaint?: unknown;
}

const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;

/** Bir regex alanını güvenlik kontrollerinden geçirerek derler. */
function safeRegex(src: unknown, flags: unknown, where: string, warn: (m: string) => void): RegExp | null {
  if (!isStr(src)) return null;
  if (src.length > MAX_PATTERN_LEN) {
    warn(`${where}: desen ${src.length} karakter (üst sınır ${MAX_PATTERN_LEN}) — reddedildi.`);
    return null;
  }
  if (NESTED_QUANTIFIER.test(src)) {
    warn(`${where}: desen iç içe niceleyici içeriyor (ReDoS riski) — reddedildi.`);
    return null;
  }
  // `g` bayrağı `test()` çağrılarını stateful yapar ve dosyaları rastgele atlatır
  // (scanner.ts'te belgelenmiş tuzak). Harici kurallarda tamamen yasaklanır.
  const f = isStr(flags) ? flags.replace(/[gy]/g, "") : "";
  try {
    return new RegExp(src, f);
  } catch (err) {
    warn(`${where}: geçersiz regex — ${String(err)}`);
    return null;
  }
}

function toRule(raw: RawRule, where: string, warn: (m: string) => void): SourceRule | null {
  const id = raw.id;
  if (!isStr(id)) {
    warn(`${where}: \`id\` zorunlu ve string olmalı — atlandı.`);
    return null;
  }
  const w = (m: string): void => warn(`${where} (${id}): ${m}`);

  const module = raw.module;
  if (!isStr(module) || !(MODULES as readonly string[]).includes(module)) {
    w(`\`module\` geçersiz (beklenen: ${MODULES.join("|")}) — atlandı.`);
    return null;
  }
  const severity = raw.severity;
  if (!isStr(severity) || !(SEVERITIES as readonly string[]).includes(severity)) {
    w(`\`severity\` geçersiz (beklenen: ${SEVERITIES.join("|")}) — atlandı.`);
    return null;
  }
  const pattern = safeRegex(raw.pattern, raw.flags, `${where} (${id})`, warn);
  if (pattern === null) return null;
  if (!isStr(raw.title) || !isStr(raw.impact) || !isStr(raw.recommendation)) {
    w("`title`, `impact` ve `recommendation` zorunlu — atlandı.");
    return null;
  }

  const effort = raw.effort === "S" || raw.effort === "M" || raw.effort === "L" ? raw.effort : "M";
  const confidence: Confidence =
    raw.confidence === "high" || raw.confidence === "medium" || raw.confidence === "low"
      ? raw.confidence
      : // Harici kuralın güveni bilinemez; varsayılan DÜŞÜK. Yerleşik kurallarla eşit
        // muamele görmesi, doğrulanmamış bir kuralın raporun başına çıkması demekti.
        "low";

  const pathInclude = safeRegex(raw.pathInclude, raw.flags, `${where} (${id}) pathInclude`, warn);
  const pathExclude = safeRegex(raw.pathExclude, raw.flags, `${where} (${id}) pathExclude`, warn);
  const refs = Array.isArray(raw.references) ? raw.references.filter(isStr) : [];
  const maxPerFile = typeof raw.maxPerFile === "number" && raw.maxPerFile > 0 ? raw.maxPerFile : undefined;

  return {
    id,
    check: isStr(raw.check) ? raw.check : id,
    module: module as ModuleId,
    title: raw.title,
    severity: severity as Severity,
    category: isStr(raw.category) ? raw.category : "Custom Rule",
    confidence,
    pattern,
    ...(pathInclude ? { pathInclude } : {}),
    ...(pathExclude ? { pathExclude } : {}),
    impact: raw.impact,
    recommendation: raw.recommendation,
    ...(refs.length > 0 ? { references: refs } : {}),
    effort,
    ...(maxPerFile !== undefined ? { maxPerFile } : {}),
    ...(raw.taintAware === true ? { taintAware: true } : {}),
    // `requiresTaint` yalnızca `taintAware` ile anlamlıdır; tek başına verilirse yok sayılır.
    ...(raw.requiresTaint === true && raw.taintAware === true ? { requiresTaint: true } : {}),
  };
}

/**
 * `warden-rules/*.yml` altındaki kural paketlerini yükler.
 * Hiç dosya yoksa boş sonuç döner (uyarı üretmez — paket kullanmak zorunlu değil).
 */
export function loadRulePacks(ctx: DetectContext): RulePackLoad {
  const files = ctx.find((p) => p.startsWith(`${RULE_PACK_DIR}/`) && /\.ya?ml$/i.test(p), { limit: 100 });
  const rules: SourceRule[] = [];
  const warnings: string[] = [];
  const seen = new Set<string>();
  const warn = (m: string): void => void warnings.push(m);

  for (const file of files) {
    const text = ctx.readFile(file);
    if (text === null) {
      warn(`${file}: okunamadı.`);
      continue;
    }
    let doc: unknown;
    try {
      doc = parse(text);
    } catch (err) {
      warn(`${file}: YAML ayrıştırılamadı — ${String(err)}`);
      continue;
    }
    const list = (doc as { rules?: unknown } | null)?.rules;
    if (!Array.isArray(list)) {
      warn(`${file}: kök seviyede \`rules:\` dizisi bekleniyordu.`);
      continue;
    }
    for (const raw of list) {
      const r = toRule((raw ?? {}) as RawRule, file, warn);
      if (r === null) continue;
      if (seen.has(r.id)) {
        warn(`${file}: \`${r.id}\` kural id'si yinelendi — ikincisi atlandı.`);
        continue;
      }
      seen.add(r.id);
      rules.push(r);
    }
  }
  return { rules, warnings, files };
}

import type { Finding, ModuleId, Confidence, EvidenceType } from "../../model/finding.ts";
import type { Severity } from "../../model/severity.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";
import { maskSecrets } from "../../secret/mask.ts";
import { VENDOR_PATH, TEST_PATH, MINIFIED_PATH } from "../../util/paths.ts";
import { buildTaintMap, evaluateTaint, adjustConfidence } from "./taint.ts";
import type { TaintMap } from "./taint.ts";
import type { CoverageCollector } from "../../report/coverage.ts";

/**
 * Bildirimsel kaynak kuralı. SAST kontrollerinin çoğu (B1/B3/B4/B6/FE) bununla ifade edilir;
 * yeni kural = bu listeye bir nesne. Her eşleşme kanıtlı (file:line) bir bulguya dönüşür.
 */
export interface SourceRule {
  readonly id: string;
  readonly check: string;
  readonly module: ModuleId;
  readonly title: string;
  readonly severity: Severity;
  readonly category: string;
  readonly confidence: Confidence;
  /** Satır bazında test edilen desen. */
  readonly pattern: RegExp;
  /**
   * Desen eşleştikten SONRA çalışan ek doğrulayıcı (opsiyonel). `false` dönerse eşleşme
   * bulguya çevrilmez. Entropi/bağlam kontrolüyle false-positive'i düşürmek için (ör. B1
   * yüksek-entropi secret). Saf ve yan-etkisiz olmalı.
   */
  readonly validate?: (line: string) => boolean;
  /** Yalnızca bu yola uyan dosyalarda çalışır (verilmezse tüm kod dosyaları). */
  readonly pathInclude?: RegExp;
  readonly pathExclude?: RegExp;
  readonly impact: string;
  readonly recommendation: string;
  readonly references?: readonly string[];
  readonly effort: "S" | "M" | "L";
  readonly evidenceType?: EvidenceType;
  /** Dosya başına aynı kuraldan en fazla bulgu (gürültüyü sınırlar). */
  readonly maxPerFile?: number;
  /**
   * Bu kural bir SINK mi — yani kullanıcı girdisi buraya ulaşırsa tehlikeli mi?
   *
   * `true` ise dosyanın taint haritası hesaplanır ve bulgunun `confidence`'ı buna göre
   * ayarlanır: girdi ulaşıyorsa yükseltilir, ulaşmıyorsa düşürülür, temizlenmişse `low`.
   * Yalnızca güven değişir — başlık/kontrol/kanıt sabit kalır, dolayısıyla fingerprint ve
   * mevcut waiver'lar korunur. Bkz. modules/sast/taint.ts.
   */
  readonly taintAware?: boolean;
  /**
   * Bu kural YALNIZCA taint kullanıcı girdisinin sink'e ulaştığını gösterirse bulgu üretir.
   *
   * Neden güvenli: `docs/STRIX-ADOPTION.md` §Sıra 3'teki asimetri gereği taint motorunun
   * **pozitif** kararı güvenilirdir (kaynaktan sink'e giden atama zinciri fiilen görülmüştür);
   * güvenilmez olan negatif kararıdır. Bu bayrak yalnızca pozitif karara dayanır.
   *
   * Ne için: `needle.get(url)` gibi sink'lerde girdi aynı satırda görünmez, bir değişkenden
   * gelir. Desen tek başına her HTTP çağrısını işaretlerdi — yanlış pozitif fabrikası. Taint
   * zorunluluğu bu kuralları kullanılabilir kılar.
   *
   * ⚠ `taintAware` ile birlikte kullanılmalı. Mevcut hiçbir kuralın görünürlüğünü azaltmaz —
   * yalnızca bu bayrağı taşıyan YENİ kuralları kapsar.
   */
  readonly requiresTaint?: boolean;
}

/** Varsayılan kod dosyası deseni. Modüller kendi `include`'unu geçerek genişletebilir (ör. FE: .html). */
export const CODE_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|vue|svelte|astro|py|go|php|rb|java|cs)$/i;

/**
 * SAST'ın atlama deseni. Artık `util/paths.ts`'teki ORTAK parçalardan türetilir — aynı bilgi
 * (vendor / test-fixture / minified) CLOUD, K8S ve parity modüllerinde de kullanılsın diye.
 * Davranış eskisiyle birebir aynı: tek genişleme `.min.css`, ve hiçbir modül `.css` taramadığı
 * için o dal ölü.
 */
export const SKIP_PATH = new RegExp(
  [VENDOR_PATH.source, MINIFIED_PATH.source, TEST_PATH.source].join("|"),
  "i",
);

export interface ScanSourceOptions {
  readonly maxFiles?: number;
  readonly maxBytesPerFile?: number;
  /**
   * Taranacak dosya deseni. Verilmezse `CODE_FILE`.
   * `g` bayrağı KULLANMA — `test()` stateful olur ve dosyaları rastgele atlar.
   */
  readonly include?: RegExp;
  /** Atlama deseni. Verilmezse `SKIP_PATH` (ek değil, YERİNE geçer). */
  readonly skip?: RegExp;
  /**
   * Dizin derinliği sınırı. Verilmezse DetectContext varsayılanı (4).
   * Derin ağaçlarda (monorepo: apps/web/src/components/ui/X.tsx = 5) yükseltmek gerekir.
   */
  readonly maxDepth?: number;
  /**
   * Kapsam toplayıcı. Verilirse boyut tavanı ve kural-başına-bulgu tavanı kesmeleri
   * kaydedilir; verilmezse davranış eskisiyle aynı (sessiz kırpma).
   */
  readonly coverage?: CoverageCollector | undefined;
}

/** Kaynak ağacını tarar; kural setini uygular; kanıtlı bulgular döndürür. */
export function scanSource(ctx: DetectContext, rules: readonly SourceRule[], opts: ScanSourceOptions = {}): Finding[] {
  const maxFiles = opts.maxFiles ?? 5000;
  const maxBytes = opts.maxBytesPerFile ?? 1_000_000;
  const include = opts.include ?? CODE_FILE;
  const skip = opts.skip ?? SKIP_PATH;

  const files = ctx.find((p) => include.test(p) && !skip.test(p), {
    limit: maxFiles,
    ...(opts.maxDepth !== undefined ? { maxDepth: opts.maxDepth } : {}),
  });
  const findings: Finding[] = [];
  const seen = new Set<string>();

  // Taint haritası dosya başına EN FAZLA BİR KEZ, ve yalnızca o dosyada taint-farkındalı
  // bir kural gerçekten eşleşirse hesaplanır (tembel). Sink'ler seyrek olduğu için tipik
  // taramada haritanın maliyeti hiç ödenmez.
  const taintAwareExists = rules.some((r) => r.taintAware);

  for (const file of files) {
    const text = ctx.readFile(file);
    if (text === null) continue;
    if (text.length > maxBytes) {
      // Eskiden sessizdi: 1 MB üstü bir dosya (üretilmiş client, birleştirilmiş config,
      // büyük seed) hiç taranmıyor ama rapor bunu "temiz" gösteriyordu.
      opts.coverage?.limit(
        "size",
        "file-size",
        `Dosya boyutu tavanı (${Math.round(maxBytes / 1000)} KB) aşıldığı için bu dosyalar hiç taranmadı.`,
        file,
      );
      continue;
    }
    opts.coverage?.fileScanned(file);

    /*
     * "Tarandı" ile "denetlendi" aynı şey değil.
     *
     * `.rb` ve `.java` CODE_FILE desenine uyduğu için okunuyor ve rapor bu dillerde "0 bulgu"
     * gösteriyor — ama dile ÖZGÜ tek bir kural yok; yalnızca genel secret/entropi kuralları
     * çalışıyor. Denetlenmemişin temiz gibi sunulması, kapsam boşluklarının en tehlikeli türü.
     *
     * Ölçüt bilinçli olarak `pathInclude` taşıyan kurallar: bunlar bir dile bağlanmış
     * kurallardır. Hiçbiri bu dosyaya uymuyorsa, o dil için derinlemesine denetim yok demektir.
     */
    if (opts.coverage) {
      const ext = /\.([a-z0-9]+)$/i.exec(file)?.[1]?.toLowerCase() ?? "?";
      let langSpecific = 0;
      for (const r of rules) if (r.pathInclude?.test(file) === true) langSpecific++;
      if (langSpecific === 0) {
        opts.coverage.limit(
          `no-lang-rules:${ext}`,
          "no-rules-for-language",
          `\`.${ext}\` dosyaları okundu ama bu dile ÖZGÜ kural yok — yalnızca genel kurallar ` +
            "çalıştı. Bu dilde \"0 bulgu\", \"denetlendi ve temiz\" anlamına gelmez.",
          file,
        );
      }
    }

    const lines = text.split(/\r?\n/);
    let taintMap: TaintMap | null = null;
    const getTaintMap = (): TaintMap => (taintMap ??= buildTaintMap(lines));

    for (const rule of rules) {
      if (rule.pathInclude && !rule.pathInclude.test(file)) continue;
      if (rule.pathExclude && rule.pathExclude.test(file)) continue;
      let hits = 0;
      const cap = rule.maxPerFile ?? 3;
      let i = 0;
      for (; i < lines.length && hits < cap; i++) {
        const line = lines[i] as string;
        rule.pattern.lastIndex = 0;
        if (!rule.pattern.test(line)) continue;
        if (rule.validate && !rule.validate(line)) continue;

        // Taint: yalnızca sink kurallarında, yalnızca eşleşme olduktan sonra.
        const taint =
          taintAwareExists && rule.taintAware ? evaluateTaint(getTaintMap(), line, i + 1) : null;

        // Taint zorunlu kurallar: girdi ulaşmıyorsa (ya da temizlenmişse) bulgu ÜRETİLMEZ.
        // Elenen eşleşme `hits` sayılmaz — aksi halde dosya başına tavan, hiç raporlanmamış
        // eşleşmelerle dolar ve gerçek bulgular sessizce kırpılırdı.
        if (rule.requiresTaint && (taint === null || !taint.reached || taint.sanitized)) continue;

        hits++;
        const confidence = rule.taintAware ? adjustConfidence(rule.confidence, taint) : rule.confidence;

        const f = makeFinding({
          id: `${rule.id}:${file}:${i + 1}`,
          title: rule.title,
          severity: rule.severity,
          module: rule.module,
          check: rule.check,
          category: rule.category,
          confidence,
          ...(taint ? { taint } : {}),
          evidence: [
            {
              type: rule.evidenceType ?? "file",
              source: file,
              location: String(i + 1),
              excerpt: maskSecrets(line.trim().slice(0, 200)),
            },
          ],
          impact: rule.impact,
          recommendation: rule.recommendation,
          effort: rule.effort,
          autoFixable: false,
          ...(rule.references ? { references: rule.references } : {}),
        });
        if (seen.has(f.fingerprint)) continue;
        seen.add(f.fingerprint);
        findings.push(f);
      }
      // Tavana ulaşıldı ve dosyada henüz taranmamış satır kaldı: bu kural için dosyanın
      // geri kalanına HİÇ bakılmadı. Eskiden sessizdi — kullanıcı 3 bulguyu düzeltip yeniden
      // tarıyor, aynı dosyadan 3 tane daha "yeni bulgu" çıkıyordu ve delta anlamsızlaşıyordu.
      if (hits >= cap && i < lines.length) {
        opts.coverage?.limit(
          "per-file-cap",
          "per-file-cap",
          `Kural başına dosya içi bulgu tavanına ulaşıldı; bu dosyaların kalan satırları o kural için taranmadı. Gerçek bulgu sayısı gösterilenden FAZLA olabilir.`,
          `${file} (${rule.id})`,
        );
      }
    }
  }
  return findings;
}

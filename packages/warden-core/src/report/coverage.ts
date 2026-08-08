import type { ModuleId } from "../model/finding.ts";

/**
 * KAPSAM BEYANI — Warden'ın "neyi göremediğini" ölçen ve beyan eden katman.
 *
 * Neden var: v0.11'e kadar motorun her katmanında SESSİZ kırpma vardı — dizin derinliği,
 * dosya sayısı, dosya boyutu, kural başına bulgu sınırı, çöken modül, kurulu olmayan harici
 * araç. Hiçbiri rapora yansımıyordu. Sonuç: "bakamadım" ile "baktım, temiz" aynı görünüyordu.
 *
 * Bir güvenlik aracı için bu, kaçırılan zafiyetten daha tehlikelidir — kullanıcıya hak
 * etmediği güveni verir. Bu dosya o farkı geri getirir: her kayıp SAYILIR ve RAPORLANIR.
 *
 * Tasarım kuralı: bu katman ASLA bulgu üretmez, ASLA bulguyu bastırmaz ve fingerprint'e
 * girmez. Yalnızca "ne görüldü / ne görülmedi" bilgisini taşır. Böylece mevcut waiver'lar,
 * delta geçmişi ve `history.jsonl` trendi aynen korunur (bkz. docs/STRIX-ADOPTION.md §K5).
 */

/**
 * Kapsam kaybı türleri.
 *
 * ⚠ **Bu listeye eklenen her tür GERÇEKTEN ÜRETİLMELİDİR.** Tanımlı ama hiç doldurulmayan bir
 * sayaç, olmayan bir güvenceyi varmış gibi gösterir — ve hiçbir test onu yakalamaz, çünkü
 * "her zaman sıfır" geçerli bir sonuç gibi görünür.
 *
 * Bu teorik bir kaygı değil: KICS'in `Counters` struct'ı `files_failed_to_scan` alanını
 * tanımlar ama üretim tarama yolunda hiç set etmez — bozuk bir dosya verildiğinde bile 0 döner.
 * Warden'ın kendi ilk uygulamasında da `git-history`, `tool-missing` ve
 * `no-rules-for-language` tanımlanmış ama bağlanmamıştı; aynı hata sınıfı.
 *
 * `test/coverage.test.ts` her türün en az bir üretim çağrısı olduğunu zorlar.
 */
export const LIMIT_KINDS = [
  /** Dizin derinliği sınırı aşıldı — alt ağaç hiç görülmedi. */
  "depth",
  /** Dosya sayısı tavanına ulaşıldı — kalan dosyalar hiç listelenmedi. */
  "file-count",
  /** Dosya boyut tavanı aşıldı — dosya okundu ama taranmadı. */
  "file-size",
  /** Kural başına dosyada bulgu tavanı — aynı türden başka eşleşmeler var ama raporlanmadı. */
  "per-file-cap",
  /** Git geçmişi taraması pencere sınırıyla kesildi. */
  "git-history",
  /** Harici araç kurulu değil / çalışmadı — o kontrol hiç yapılmadı. */
  "tool-missing",
  /** Dosya taranabilirdi ama hiçbir kural o dili kapsamıyor. */
  "no-rules-for-language",
] as const;

export type LimitKind = (typeof LIMIT_KINDS)[number];

export interface LimitHit {
  readonly kind: LimitKind;
  /** İnsan-okunur açıklama; raporda bu cümle görünür. */
  readonly detail: string;
  /** Kaç kez tetiklendi. */
  readonly count: number;
  /** İlk birkaç somut örnek (yol / dosya / dil). Tam liste değil — rapor şişmesin. */
  readonly samples: readonly string[];
}

/** Bir modülün bu çalışmadaki kapsam durumu. */
export type ModuleStatus =
  /** Çalıştı ve denetleyecek gerçek bir yüzey buldu. */
  | "audited"
  /** Çalıştı ama denetlenecek yüzey yoktu (ör. projede ödeme entegrasyonu yok). */
  | "surface-absent"
  /** Hiç çalışmadı (aktif modül + kapalı yetki kapısı, ya da stack uyumsuz). */
  | "not-run"
  /** Çalışırken hata verdi — bu boyut DENETLENMEDİ. */
  | "failed";

export interface ModuleCoverage {
  readonly module: ModuleId;
  readonly title: string;
  readonly status: ModuleStatus;
  /** Neden bu durumda — raporda gösterilir. */
  readonly reason: string | null;
  /** Modülün incelediği yüzey öğesi sayısı (biliniyorsa). `null` = modül bildirmedi. */
  readonly surface: number | null;
  readonly findings: number;
}

export interface CoverageManifest {
  /** Kural taramasında gerçekten okunan benzersiz dosya sayısı. */
  readonly filesScanned: number;
  /** Bir sınır yüzünden hiç görülmeyen/taranmayan dosya sayısı (bilinen alt sınır). */
  readonly filesSkipped: number;
  /**
   * Dosya kapsamı yüzdesi: taranan / (taranan + atlanan).
   * `null` = hiç dosya taranmadı (ölçülemez).
   *
   * Bu KASITLI olarak tek bir "genel kapsam" skoru değil. Tek bir yüzde uydurmak, tam da bu
   * katmanın düzeltmek için var olduğu şeyi (ölçülmemişi ölçülmüş göstermek) tekrarlardı.
   */
  readonly fileCoveragePercent: number | null;
  readonly limits: readonly LimitHit[];
  readonly modules: readonly ModuleCoverage[];
  /** Kapsam beyanının kendisinin eksik olduğu yerler (henüz ölçmediğimiz şeyler). */
  readonly unmeasured: readonly string[];
}

/**
 * Tarama boyunca yaşayan, kapsam kayıplarını biriktiren toplayıcı.
 *
 * Mutable ve tek bir tarama çalışmasına aittir. Modüller ve dosya katmanı buraya yazar;
 * orkestratör sonunda `build()` ile dondurur.
 */
export class CoverageCollector {
  private readonly hits = new Map<
    string,
    { kind: LimitKind; detail: string; count: number; samples: string[]; seen: Set<string> | null }
  >();
  private readonly moduleRows: ModuleCoverage[] = [];
  private readonly scannedFiles = new Set<string>();
  private readonly unmeasuredNotes = new Set<string>();

  /** En fazla kaç somut örnek saklansın (rapor şişmesin diye). */
  private static readonly MAX_SAMPLES = 5;

  /**
   * Bir kapsam kaybını kaydet.
   *
   * `sample` verilirse kayıp ONA GÖRE BENZERSİZLEŞTİRİLİR. Bu şart: `ctx.find()` her modül
   * tarafından yeniden çağrıldığı için aynı derinlik kesmesi 18 kez tetiklenir. Benzersizleştirme
   * olmadan rapor "142 dizin kesildi" derdi — oysa gerçek sayı 8 olabilir. Kapsamı olduğundan
   * kötü göstermek de yanlış beyandır.
   *
   * @param key Aynı kaybı gruplamak için sabit anahtar (ör. "depth", "size:sast").
   */
  limit(key: string, kind: LimitKind, detail: string, sample?: string): void {
    let row = this.hits.get(key);
    if (row === undefined) {
      row = { kind, detail, count: 0, samples: [], seen: sample === undefined ? null : new Set() };
      this.hits.set(key, row);
    }
    if (sample !== undefined && row.seen !== null) {
      if (row.seen.has(sample)) return;
      row.seen.add(sample);
      if (row.samples.length < CoverageCollector.MAX_SAMPLES) row.samples.push(sample);
    }
    row.count++;
  }

  /** Kural taramasında gerçekten okunan bir dosyayı işaretle (benzersizleştirilir). */
  fileScanned(relPath: string): void {
    this.scannedFiles.add(relPath);
  }

  /** Henüz ölçemediğimiz bir kapsam boşluğunu beyan et (dürüstlük notu). */
  unmeasured(note: string): void {
    this.unmeasuredNotes.add(note);
  }

  module(row: ModuleCoverage): void {
    this.moduleRows.push(row);
  }

  get scannedCount(): number {
    return this.scannedFiles.size;
  }

  build(): CoverageManifest {
    const limits = [...this.hits.values()]
      .map((h) => ({ kind: h.kind, detail: h.detail, count: h.count, samples: [...h.samples] }))
      .sort((a, b) => b.count - a.count);

    // Atlanan dosya sayısı BİLİNEN ALT SINIRDIR: derinlik sınırında kesilen bir dizinin
    // altında kaç dosya olduğunu saymıyoruz (saymak için o ağacı yürümek gerekirdi — yani
    // sınırın var oluş sebebini iptal etmek). Bu belirsizlik `unmeasured` ile beyan edilir.
    const skipped = limits
      .filter((l) => l.kind === "file-size" || l.kind === "file-count")
      .reduce((a, l) => a + l.count, 0);

    const scanned = this.scannedFiles.size;
    const denom = scanned + skipped;

    return {
      filesScanned: scanned,
      filesSkipped: skipped,
      fileCoveragePercent: denom === 0 ? null : Math.round((scanned / denom) * 1000) / 10,
      limits,
      modules: [...this.moduleRows],
      unmeasured: [...this.unmeasuredNotes],
    };
  }
}

/** Hiçbir şey toplamayan collector — testler ve collector geçirmeyen çağrı yolları için. */
export const NOOP_COVERAGE = new CoverageCollector();

/**
 * Paylaşılan yol filtreleri — "bu dosya gerçek üretim kodu/altyapısı mı?" sorusunun TEK kaynağı.
 *
 * Neden tek kaynak: bu bilgi eskiden dört ayrı yerde, dört farklı biçimde duruyordu
 * (`detect/fs.ts` IGNORE_DIRS · `sast/scanner.ts` SKIP_PATH · `cloud`/`k8s` kendi dar SKIP'leri ·
 * `sast/git-history.ts` git pathspec'leri) ve ikisi test/fixture yollarını eliyor, ikisi elemiyordu.
 * Fark, `ctx.find()` varsayılan derinliği 4 iken görünmüyordu: derin fixture'lara zaten
 * ulaşılamıyordu. Derinlik 6'ya çıkınca (bkz. detect/fs.ts DEFAULT_MAX_DEPTH) CLOUD/K8S/parity
 * modülleri `test/fixtures/vuln-*` altındaki KASITLI zafiyetli örnekleri gerçek altyapı sanıp
 * P0 bulgu üretmeye başladı.
 *
 * Bu bir Warden'a özgü sorun değil: her projede örnek/şablon/fixture dizinleri olur ve bir
 * denetim aracının onları gerçek bulgu diye raporlaması, raporun tamamına olan güveni düşürür.
 */

/**
 * Vendor / build çıktısı dizinleri. Hiçbir modül burada proje kodu aramamalı: üretilmiş,
 * kopyalanmış ya da üçüncü-parti içerik.
 */
export const VENDOR_PATH = /(^|\/)(node_modules|dist|build|\.next|coverage|warden-report|vendor)\//i;

/**
 * Test / fixture yolları. Buradaki zafiyetler kasıtlıdır (regresyon fixture'ları, örnek kötü
 * kod) — gerçek bulgu değildir.
 *
 * ⚠ Bu desen YOLA bakar, dosyanın içeriğine değil. Testler fixture dizinini `projectRoot`
 * OLARAK verdiğinde (bkz. test/parity-integration.test.ts) göreli yollar `test/fixtures/`
 * öneki taşımaz, dolayısıyla bu filtre devreye girmez ve fixture temelli testler çalışmaya
 * devam eder. Kasıtlı davranış: "fixture" olmak bir dosyanın *çevreleyen projedeki konumu*,
 * kendi özelliği değil.
 */
export const TEST_PATH = /\.(test|spec)\.[a-z]+$|(^|\/)(test|tests|__tests__|fixtures)\//i;

/** Küçültülmüş/derlenmiş bundle — satır bazlı analiz burada anlamsız (tek satır, on binlerce sütun). */
export const MINIFIED_PATH = /\.min\.(js|css)$/i;

/**
 * Bir yol gerçek, denetlenmeye değer proje içeriği mi?
 * Vendor/build, test/fixture ve minified dosyalar elenir.
 */
export function isRealSourcePath(relPath: string): boolean {
  return !VENDOR_PATH.test(relPath) && !TEST_PATH.test(relPath) && !MINIFIED_PATH.test(relPath);
}

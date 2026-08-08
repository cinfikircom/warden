import type { Finding } from "../model/finding.ts";

/**
 * DOĞRULAMA NOTLARI — "bu bulgu hangi durumlarda yanlış pozitiftir?"
 *
 * Strix'ten devralınan ikinci kalem: her zafiyet dosyasındaki `## False Positives` ve
 * `## Validation` bölümleri. Bunlar bir LLM'e "acele karar verme" demek için yazılmıştı;
 * deterministik bir tarayıcıda karşılığı, bulguyu SUNARKEN sınırını da söylemektir.
 *
 * Neden değerli: Warden'ın en büyük yapısal zaafı satır-bazlı regex'in bağlam körlüğü.
 * O körlüğü tamamen kapatmak AST + çağrı grafı ister (Faz B). Ama körlüğü **beyan etmek**
 * bugün mümkün ve kullanıcıyı körlemesine düzeltme yapmaktan kurtarır: "şu üç durumda bu
 * bulgu gerçek değildir, önce onu kontrol et."
 *
 * Bu, Kapsam Beyanı ile aynı ilkenin bulgu düzeyindeki hâli — aracın kendi sınırını
 * gizlememesi. Ve waiver yazarken doğrudan gerekçe malzemesi olur.
 *
 * ⚠ Bu notlar bulguyu BASTIRMAZ, güvenini DÜŞÜRMEZ ve fingerprint'e girmez. Yalnızca
 * rapora ve remediation playbook'una eklenen bir bölümdür.
 *
 * Kaynak: Strix (OmniSecure Inc., Apache-2.0) — olgusal doğrulama bilgisi.
 * Bkz. docs/STRIX-ADOPTION.md §1.7
 */

/**
 * Anahtar: kural id ön-eki ya da check kodu. Daha uzun (daha spesifik) anahtar kazanır.
 */
const FP_HINTS: Readonly<Record<string, readonly string[]>> = {
  // --- Enjeksiyon ailesi ---
  "B6-sql": [
    "Sorgu parametreli API ile çalışıyorsa (`?`, `$1`, `:name` yer tutucuları) enjeksiyon yoktur — birleştirme yalnızca görünürde olabilir.",
    "Birleştirilen değer sabit bir allow-list'ten geliyorsa (sütun/tablo adı sözlüğü) risk yoktur; kullanıcı girdisi doğrudan geçmiyordur.",
    "Değer aynı fonksiyonda `Number()`/`parseInt` ile sayıya çevrilmişse enjeksiyon taşıyamaz.",
  ],
  "B6-nosql": [
    "Girdi `String(x)` ile stringe zorlanıyorsa operator injection (`{$ne: null}`) mümkün değildir.",
    "Şema doğrulaması (Zod/Joi/Mongoose strict) tipi kısıtlıyorsa nesne enjeksiyonu engellenir.",
  ],
  "B6-cmd": [
    "Komut `execFile`/`spawn` ile ARGÜMAN DİZİSİ olarak çağrılıyorsa kabuk yorumlaması yoktur.",
    "Değer sabit bir komut sözlüğünden seçiliyorsa (switch/map) kullanıcı girdisi kabuğa ulaşmaz.",
  ],
  "B6-eval": [
    "`eval`'e giden ifade tamamen sabitse (yapılandırma sabiti, test verisi) sömürülebilir değildir.",
    "Değer bir sayı/enum doğrulamasından geçiyorsa kod çalıştırma yüzeyi kapanır.",
  ],
  "B6-ssrf": [
    "Hedef host bir allow-list'e karşı doğrulanıyorsa SSRF yoktur — doğrulamanın DNS çözümlemesinden SONRA olması gerekir (rebinding).",
    "URL sabit bir taban adrese ekleniyorsa (`BASE + path`) ve şema/host kullanıcıdan gelmiyorsa risk sınırlıdır.",
  ],
  "B6-path": [
    "`path.basename()` uygulanmışsa dizin geçişi engellenmiştir.",
    "Yol, izin verilen kök dizinle `path.resolve` sonrası `startsWith` kontrolünden geçiyorsa güvenlidir.",
  ],
  "B6-redos": [
    "Regex yalnızca sabit/geliştirici kontrolündeki metne uygulanıyorsa DoS yüzeyi yoktur.",
    "Girdi uzunluğu regex'ten önce sınırlanıyorsa (ör. `.slice(0, 64)`) backtracking patlaması pratikte imkânsızdır.",
  ],
  // --- Secret ---
  "B1": [
    "Değer bir PLACEHOLDER ise (`changeme`, `your-key-here`, `xxx`) gerçek bir sır değildir — yine de dağıtımda gerçek değerle değişmesi gerekir.",
    "Örnek/dokümantasyon dosyasındaki (`.env.example`, README) değerler kasıtlıdır.",
    "Test fixture'larındaki sahte anahtarlar gerçek maruziyet değildir; yine de gerçek bir anahtara benziyorsa rotasyon ucuzdur.",
  ],
  "B2": [
    "Zafiyet, paketin KULLANILMAYAN bir alt modülündeyse etki sınırlı olabilir — Warden'ın reachability sinyali bunu kısmen ölçer.",
    "Yalnızca dev bağımlılığıysa üretim çalışma zamanını etkilemez, ancak CI/derleme zincirini etkileyebilir.",
  ],
  // --- Erişim kontrolü ---
  "ACC-2": [
    "Kimlik doğrulama router seviyesinde uygulanıyorsa (`router.use(requireAuth)`) tek tek route'larda görünmez ama etkindir.",
    "Endpoint kasıtlı olarak herkese açıksa (webhook, health, public API) bulgu geçerli değildir — waiver yazın.",
  ],
  "ACC-1": [
    "Sorgu oturumdaki kullanıcıya göre filtreleniyorsa (`where: { id, userId: session.userId }`) IDOR yoktur.",
    "Kaynak zaten herkese açıksa (public profil) sahiplik kontrolü gerekmez.",
  ],
  "ACC-3": [
    "Şema doğrulayıcı (Zod/Joi/DTO) yalnızca izin verilen alanları geçiriyorsa over-posting engellenmiştir.",
    "ORM seviyesinde `select`/`fillable` allow-list'i varsa istek gövdesinin tamamı yazılmaz.",
  ],
  // --- Auth ---
  "AUTH-7": [
    "Parola hash'leme ayrı bir servise/kimlik sağlayıcıya (Auth0, Cognito, Keycloak) devredilmişse uygulama kodunda hash görünmez ve bulgu geçersizdir.",
    "Hash bir veritabanı fonksiyonuyla (pgcrypto `crypt()`) yapılıyorsa kod tarafında çağrı olmayabilir.",
  ],
  "AUTH-8": [
    "Oturum sunucu tarafında tutulmuyorsa (stateless JWT) `regenerate` kavramı geçerli değildir; bunun yerine token rotasyonu aranmalı.",
  ],
  "AUTH-9": [
    "Mesajlar kullanıcıya değil yalnızca sunucu log'una gidiyorsa enumeration yüzeyi yoktur.",
    "Kayıt akışı zaten e-postanın varlığını açıkça bildiriyorsa (tasarım kararı) bu ayrım ek bilgi sızdırmaz.",
  ],
  // --- Frontend ---
  "FE-3": [
    "İçerik bir sanitizer'dan (DOMPurify, sanitize-html) geçiyorsa XSS yüzeyi kapalıdır.",
    "Değer tamamen geliştirici kontrolündeki sabit bir metinse (i18n anahtarı, ikon SVG'si) risk yoktur.",
  ],
  "FE-8": [
    "Şablona giren değerler sunucuda zaten kaçışlanıyorsa (controller'da `escapeHtml`) çift kaçış olabilir ama XSS olmaz.",
    "İlgili şablon yalnızca yetkili/iç kullanıcılara render ediliyorsa etki düşer — ama kaçışı açmak yine de doğrudur.",
  ],
  "FE-2": [
    "CSP raporlama modundaysa (`Content-Security-Policy-Report-Only`) üretim davranışını engellemez; yine de gerçek politikanın ayrıca sıkılaştırılması gerekir.",
  ],
  // --- Veri gizliliği ---
  "PRIV-1": [
    "Log satırı maskeleme uyguluyorsa (`mask(email)`) PII sızmaz.",
    "Log yalnızca geliştirme ortamında etkinse (`if (isDev)`) üretim maruziyeti yoktur.",
  ],
  "PRIV-3": [
    "Şifreleme veritabanı katmanında (TDE, şifreli birim) yapılıyorsa kodda görünmez; ancak alan-düzeyi şifreleme ile aynı korumayı sağlamaz.",
  ],
  // --- Web ---
  "WEB-1": [
    "API yalnızca `Authorization` başlığıyla (çerezsiz) çalışıyorsa CSRF yüzeyi yoktur — tarayıcı başlığı otomatik göndermez.",
    "`SameSite=Strict/Lax` çerezler çoğu CSRF senaryosunu kapatır; token yine de derinlemesine savunmadır.",
  ],
};

/** Bir bulgu için doğrulama notları. Eşleşme yoksa boş dizi. */
export function fpHintsFor(f: Pick<Finding, "id" | "check">): readonly string[] {
  const keys = Object.keys(FP_HINTS)
    .filter((k) => f.id.startsWith(k) || f.check === k)
    .sort((a, b) => b.length - a.length);
  const first = keys[0];
  return first === undefined ? [] : (FP_HINTS[first] ?? []);
}

/** Kaç kontrol için doğrulama notu tanımlı (kapsam raporlaması için). */
export const FP_HINT_COVERAGE = Object.keys(FP_HINTS).length;

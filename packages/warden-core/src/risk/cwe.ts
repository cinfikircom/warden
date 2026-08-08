import type { Finding } from "../model/finding.ts";

/**
 * CWE (Common Weakness Enumeration) eşlemesi.
 *
 * Strix'ten devralınan kalem: `tools/reporting/tool.py` içindeki küratörlü CWE tablosu ve
 * onunla gelen — asıl değerli olan — kural:
 *
 *   **EN SPESİFİK child CWE kullanılır, parent DEĞİL.**
 *
 * Neden önemli: CWE-74 ("Injection") gibi bir parent, SQL enjeksiyonu ile komut enjeksiyonunu
 * aynı kutuya koyar. Bir tarayıcı çıktısının değeri, hangi zafiyet sınıfı olduğunu KESİN
 * söylemesindedir; parent CWE "bir tür enjeksiyon" demektir ve düzeltmeyi yönlendirmez.
 * Uyum raporlamasında da parent'lar reddedilir.
 *
 * Bu yüzden `FORBIDDEN_PARENTS` listesi bir testle zorlanır: tabloya yanlışlıkla bir parent
 * girerse test kırılır.
 *
 * Kaynak: Strix (OmniSecure Inc., Apache-2.0) — olgusal eşleme verisi.
 * Bkz. docs/STRIX-ADOPTION.md §1.7
 */

/** Asla kullanılmaması gereken parent CWE'ler — çok genel, düzeltmeyi yönlendirmez. */
export const FORBIDDEN_PARENTS: readonly string[] = [
  "CWE-74", // Injection (genel) → 89/78/79/94 kullan
  "CWE-20", // Improper Input Validation → somut sınıfı kullan
  "CWE-200", // Information Exposure → 209/532/538 kullan
  "CWE-284", // Improper Access Control → 862/863/639 kullan
  "CWE-693", // Protection Mechanism Failure → somut mekanizmayı söyle
];

/**
 * Warden check/kural ön-eki → CWE.
 *
 * Daha uzun anahtar önce denenir: `B6-ssrf` → CWE-918, ama `B6` → CWE-89. Böylece aynı
 * check kodu altındaki farklı zafiyet sınıfları doğru CWE'yi alır.
 */
const CWE_BY_RULE: Readonly<Record<string, string>> = {
  // --- B6 injection ailesi: her biri kendi spesifik CWE'si ---
  "B6-sql": "CWE-89",
  "B6-nosql": "CWE-943",
  "B6-ldap": "CWE-90",
  "B6-cmd": "CWE-78",
  "B6-command": "CWE-78",
  "B6-shell": "CWE-78",
  "B6-exec": "CWE-78",
  "B6-eval": "CWE-95",
  "B6-ssti": "CWE-1336",
  "B6-ssrf": "CWE-918",
  "B6-path": "CWE-22",
  "B6-traversal": "CWE-22",
  "B6-xxe": "CWE-611",
  "B6-redos": "CWE-1333",
  "B6-dotnet-sql": "CWE-89",
  "B6-go-sql": "CWE-89",
  "B6-laravel-raw": "CWE-89",
  // --- Diğer B kontrolleri ---
  "B1": "CWE-798", // hardcoded credentials
  "B2": "CWE-1395", // vulnerable third-party component
  "B3-iv": "CWE-329", // statik IV
  "B3-rng": "CWE-338", // güvensiz PRNG
  "B3": "CWE-327", // zayıf/bozuk kripto algoritması
  "B4-alg-none": "CWE-347", // imza doğrulaması hatalı
  "B4-weak-secret": "CWE-521",
  "B4": "CWE-613", // yetersiz oturum sonlandırma (uzun TTL)
  "B5": "CWE-639", // IDOR / yetkilendirme atlatma
  "B6": "CWE-89", // kalan enjeksiyonlar için varsayılan
  "B7-open-redirect": "CWE-601",
  "B7-tls": "CWE-295",
  "B7": "CWE-942", // izin verilen fazla geniş CORS
  "B8": "CWE-502", // güvensiz deserialization
  "B9": "CWE-209", // hata mesajıyla bilgi sızıntısı
  // --- Modüller ---
  "ACC-1": "CWE-639",
  "ACC-2": "CWE-862", // eksik yetkilendirme
  "ACC-3": "CWE-915", // mass assignment
  "ACC-4": "CWE-269", // ayrıcalık yönetimi
  "AUTH-1": "CWE-308", // tek faktörlü kimlik doğrulama
  "AUTH-2": "CWE-330", // yetersiz rastgelelik
  "AUTH-3": "CWE-1004", // httpOnly olmayan çerez
  "AUTH-4": "CWE-613",
  "AUTH-5": "CWE-307", // brute-force koruması yok
  "AUTH-6": "CWE-521", // zayıf parola gereksinimi
  "AUTH-7": "CWE-256", // korumasız kimlik bilgisi saklama
  "AUTH-8": "CWE-384", // session fixation
  "AUTH-9": "CWE-204", // gözlemlenebilir yanıt farkı
  "API-1": "CWE-862",
  "API-2": "CWE-213", // amaçlanandan fazla veri ifşası
  "API-3": "CWE-770", // kaynak tüketimi sınırsız
  "API-4": "CWE-209",
  "API-6": "CWE-770",
  "WEB-1": "CWE-352", // CSRF
  "WEB-2": "CWE-1021", // clickjacking / eksik güvenlik başlıkları
  "WEB-3": "CWE-942",
  "FE-1": "CWE-922", // hassas bilginin güvensiz saklanması
  "FE-2": "CWE-1021",
  "FE-3": "CWE-79",
  "FE-4": "CWE-540", // kaynak kodda bilgi ifşası
  "FE-5": "CWE-346", // origin doğrulama hatası
  "FE-6": "CWE-1022",
  "FE-7": "CWE-353", // bütünlük kontrolü yok
  "FE-8": "CWE-79",
  "PRIV-1": "CWE-532", // log'a hassas bilgi
  "PRIV-2": "CWE-598", // GET/query string'de hassas bilgi
  "PRIV-3": "CWE-311", // şifreleme eksik
  "PRIV-4": "CWE-359", // kişisel bilginin ifşası
  "PRIV-5": "CWE-778", // yetersiz loglama
  "UPLOAD-1": "CWE-434", // tehlikeli tipte dosya yükleme
  "UPLOAD-2": "CWE-22",
  "UPLOAD-3": "CWE-770",
  "UPLOAD-4": "CWE-434",
  "EMAIL-1": "CWE-93", // CRLF enjeksiyonu
  "EMAIL-2": "CWE-79",
  "EMAIL-3": "CWE-319", // şifrelenmemiş hassas veri iletimi
  "FLOW-1": "CWE-662", // yanlış senkronizasyon
  "FLOW-2": "CWE-362", // yarış durumu
  "FLOW-3": "CWE-799", // etkileşim sıklığı kontrolsüz
  "PAY-1": "CWE-345", // veri gerçekliği doğrulanmıyor
  "PAY-2": "CWE-472", // web parametresi kurcalama
  "PAY-3": "CWE-837", // tek seferlik işlemin tekrarı
  "PAY-5": "CWE-311",
  "K8S-1": "CWE-250", // gereksiz ayrıcalıkla çalıştırma
  "K8S-2": "CWE-1104", // bakımsız üçüncü taraf bileşen
  "K8S-3": "CWE-798",
  "K8S-4": "CWE-319",
  "CLOUD": "CWE-732", // yanlış izin ataması (public bucket / IAM wildcard)
  "C1": "CWE-538", // dosya/dizin bilgisinin ifşası
  "C2": "CWE-1021", // eksik güvenlik başlıkları → clickjacking/çerçeveleme
  "C3": "CWE-319", // TLS/şifrelenmemiş iletim
  "D3": "CWE-798",
  "A2": "CWE-1188", // güvensiz varsayılan başlatma
};

/**
 * Bulguya karşılık gelen en spesifik CWE. Eşleşme yoksa `null` — uydurulmuş bir CWE,
 * eksik CWE'den kötüdür (uyum raporunda yanlış kategoriye düşer).
 */
export function cweFor(f: Pick<Finding, "id" | "check">): string | null {
  // Kural id'si daha spesifik olduğu için önce o denenir (`B6-ssrf-node-var` → `B6-ssrf`).
  const candidates = Object.keys(CWE_BY_RULE)
    .filter((k) => f.id.startsWith(k) || f.check === k)
    .sort((a, b) => b.length - a.length);
  for (const k of candidates) {
    const cwe = CWE_BY_RULE[k];
    if (cwe !== undefined && !FORBIDDEN_PARENTS.includes(cwe)) return cwe;
  }
  return null;
}

/** Bulgu kümesini CWE ile zenginleştirir. Mevcut `cwe` alanı varsa dokunulmaz. */
export function enrichCwe(findings: readonly Finding[]): Finding[] {
  return findings.map((f) => {
    if (f.cwe !== undefined) return f;
    const cwe = cweFor(f);
    return cwe === null ? f : { ...f, cwe };
  });
}

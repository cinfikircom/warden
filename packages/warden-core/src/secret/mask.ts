/**
 * Secret maskeleme (iş emri §2.4): bulunan token/parola/URL rapora `***` ile yazılır;
 * tam değer ASLA loglanmaz. Bu modül core'un tek "kanıt yazma" geçididir — tüm snippet'ler
 * rapora/log'a yazılmadan önce buradan geçirilmelidir.
 */

/** Yüksek-entropili/secret-benzeri token'ları yakalayan desenler. */
const SECRET_PATTERNS: readonly RegExp[] = [
  // key=value / key: value — anahtar adı gizli-kelime İÇEREN tanımlayıcılar (SECRET_KEY, DB_PASSWORD ...)
  /([A-Za-z0-9_]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth|bearer|session)[A-Za-z0-9_]*)\s*[:=]\s*["']?([^\s"']{4,})/gi,
  // JWT
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  // AWS access key id
  /\bAKIA[0-9A-Z]{16}\b/g,
  // Genel uzun base64/hex sırrı
  /\b[A-Fa-f0-9]{32,}\b/g,
  // Bağlantı dizesi içindeki parola: scheme://user:pass@host
  /(\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:)([^@\s/]+)(@)/gi,
];

/** Bir değeri ucu görünür biçimde maskeler: "abcd…wxyz" yerine güvenli `***`. */
export function maskValue(value: string): string {
  if (value.length <= 8) return "***";
  return `${value.slice(0, 2)}***${value.slice(-2)}`;
}

/**
 * Serbest metindeki secret-benzeri her parçayı maskeler.
 * Rapora/log'a giden HER snippet bu fonksiyondan geçmelidir.
 */
export function maskSecrets(text: string): string {
  let out = text;
  // bağlantı dizesi parolası
  out = out.replace(
    /(\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:)([^@\s/]+)(@)/gi,
    (_m, pre: string, _pw: string, post: string) => `${pre}***${post}`,
  );
  // key=value gizli alanlar (anahtar adı gizli-kelime içeren tanımlayıcılar dahil: SECRET_KEY ...)
  out = out.replace(
    /([A-Za-z0-9_]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth|bearer|session)[A-Za-z0-9_]*)(\s*[:=]\s*["']?)([^\s"']{4,})/gi,
    (_m, key: string, sep: string, val: string) => `${key}${sep}${maskValue(val)}`,
  );
  // tek-başına token'lar (JWT, AKIA, uzun hex)
  for (const re of [SECRET_PATTERNS[1], SECRET_PATTERNS[2], SECRET_PATTERNS[3]]) {
    if (!re) continue;
    out = out.replace(re, (m: string) => maskValue(m));
  }
  return out;
}

/** Bir metnin secret içerip içermediğini söyler (uyarı/işaretleme için). */
export function looksLikeSecret(text: string): boolean {
  return SECRET_PATTERNS.some((re) => {
    re.lastIndex = 0;
    return re.test(text);
  });
}

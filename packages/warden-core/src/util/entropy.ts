/**
 * Entropi yardımcıları (B1 secret tespitini güçlendirir). Gitleaks/TruffleHog'un ana
 * sinyali: yüksek Shannon entropili string'ler genellikle rastgele üretilmiş secret'lardır.
 * Saf fonksiyonlar — ağ/dosya gerektirmez, test edilebilir.
 */

/** Bir string'in Shannon entropisi (bit/karakter). Rastgele token'lar ~4.0+ döner. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Bir satırdaki tırnaklı string literalleri (', ", `) çıkarır. */
export function extractStringLiterals(line: string): string[] {
  const out: string[] = [];
  const re = /(['"`])((?:\\.|(?!\1)[^\\])*)\1/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line)) !== null) {
    if (m[2]) out.push(m[2]);
  }
  return out;
}

/**
 * Bir satırın "yüksek entropili secret" içerip içermediğini söyler. Yalnızca
 * secret-benzeri bir anahtara (key/token/secret/password...) ATANMIŞ, yeterince uzun ve
 * yüksek entropili string literalleri işaretler — placeholder/örnek değerleri eler.
 */
const SECRET_KEY_HINT =
  /\b(secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|password|passwd|pwd|auth|credential|bearer)\b/i;
// Belirgin placeholder/örnek değerler (FP önleme).
const PLACEHOLDER =
  /^(x{4,}|\.{3,}|<[^>]+>|\$\{[^}]+\}|process\.env|your[_-]|change[_-]?me|example|placeholder|dummy|test|todo|null|undefined|true|false)/i;

export function looksHighEntropySecret(line: string, minLen = 20, minEntropy = 4.0): boolean {
  if (!SECRET_KEY_HINT.test(line)) return false;
  for (const lit of extractStringLiterals(line)) {
    if (lit.length < minLen) continue;
    if (PLACEHOLDER.test(lit)) continue;
    // Boşluk içeren (cümle gibi) veya yalnızca yol/URL olanları ele.
    if (/\s/.test(lit)) continue;
    if (shannonEntropy(lit) >= minEntropy) return true;
  }
  return false;
}

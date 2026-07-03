import type { Finding } from "../model/finding.ts";
import type { DetectContext } from "../detect/types.ts";

/**
 * Import-seviyesi erişilebilirlik (reachability). Modern SCA'nın FP'yi %70–90 düşüren fikri:
 * bir bağımlılık zafiyetli olsa bile kod onu GERÇEKTEN kullanıyor mu? Tam çağrı-grafı pahalıdır;
 * bu, ucuz ama güçlü bir birinci-derece yaklaşım: paket kaynak kodun içe-aktarım grafında mı.
 *
 * reachable=false → paket manifest'te ama hiçbir yerde import edilmiyor (çoğu kez transitif) →
 * önceliği düşür. reachable=true → doğrudan import → önceliği koru. Saf/test edilebilir.
 */

const CODE_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|php)$/i;
const SKIP = /(^|\/)(node_modules|dist|build|\.next|coverage|warden-report|vendor|__pycache__)\/|\.min\.js$/i;

/** JS/TS import/require/dynamic-import'tan paket adını çıkarır (alt-yol ve @scope korunur). */
function jsPackages(text: string, out: Set<string>): void {
  const res = [
    /\bimport\b[^'"]*?from\s*['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\bimport\s*['"]([^'"]+)['"]/g,
  ];
  for (const re of res) {
    let m: RegExpExecArray | null;
    re.lastIndex = 0;
    while ((m = re.exec(text)) !== null) {
      const spec = m[1]!;
      if (spec.startsWith(".") || spec.startsWith("/")) continue; // yerel modül
      out.add(pkgRoot(spec));
    }
  }
}

/** "@scope/name/sub" → "@scope/name"; "lodash/merge" → "lodash". */
function pkgRoot(spec: string): string {
  const parts = spec.split("/");
  if (spec.startsWith("@")) return parts.slice(0, 2).join("/");
  return parts[0]!;
}

function pyPackages(text: string, out: Set<string>): void {
  const res = [/^\s*import\s+([A-Za-z0-9_.]+)/gm, /^\s*from\s+([A-Za-z0-9_.]+)\s+import/gm];
  for (const re of res) {
    let m: RegExpExecArray | null;
    re.lastIndex = 0;
    while ((m = re.exec(text)) !== null) out.add(m[1]!.split(".")[0]!);
  }
}

function goPackages(text: string, out: Set<string>): void {
  const re = /["']([a-z0-9.\-]+\/[^"'\s]+)["']/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) out.add(m[1]!);
}

/** Kaynak ağacından içe-aktarılan paket adları kümesini kurar. */
export function buildImportGraph(fs: DetectContext, opts: { maxFiles?: number } = {}): Set<string> {
  const out = new Set<string>();
  const files = fs.find((p) => CODE_FILE.test(p) && !SKIP.test(p), { limit: opts.maxFiles ?? 5000 });
  for (const f of files) {
    const text = fs.readFile(f);
    if (!text || text.length > 2_000_000) continue;
    if (/\.(ts|tsx|js|jsx|mjs|cjs)$/i.test(f)) jsPackages(text, out);
    else if (/\.py$/i.test(f)) pyPackages(text, out);
    else if (/\.go$/i.test(f)) goPackages(text, out);
  }
  return out;
}

/** Bir bağımlılık bulgusundan paket adını çıkarır (B2-vuln:<ad> / B2-osv:<ad>:<id>). */
export function packageOfFinding(f: Finding): string | null {
  const m = /^B2-(?:vuln|osv):((?:@[^:/]+\/)?[^:]+)/.exec(f.id);
  return m ? m[1]! : null;
}

/** Go modülü için: import yolu paket kök adını içerir mi (ör. github.com/x/y). */
function goReachable(pkg: string, imported: ReadonlySet<string>): boolean {
  for (const imp of imported) if (imp === pkg || imp.startsWith(pkg + "/") || pkg.startsWith(imp + "/")) return true;
  return false;
}

/**
 * Bağımlılık bulgularına erişilebilirlik ekler. reachable=false ve KEV değilse exploitability
 * düşürülür + not eklenir (öncelik azaltma). İçe-aktarım grafı boşsa dokunmaz (bilinmiyor).
 */
export function enrichReachability(findings: readonly Finding[], imported: ReadonlySet<string>): Finding[] {
  if (imported.size === 0) return [...findings];
  return findings.map((f) => {
    const pkg = packageOfFinding(f);
    if (!pkg) return f;
    const reachable = imported.has(pkg) || imported.has(pkgTop(pkg)) || goReachable(pkg, imported);
    const refs = new Set(f.references ?? []);
    refs.add(reachable ? "reachable (import grafında)" : "unreachable (import grafında yok — olası transitif)");
    const downgrade = !reachable && !f.kev;
    return {
      ...f,
      reachable,
      references: [...refs],
      ...(downgrade ? { exploitability: "low" as const } : {}),
    };
  });
}

function pkgTop(pkg: string): string {
  return pkg.startsWith("@") ? pkg : pkg.split("/")[0]!;
}

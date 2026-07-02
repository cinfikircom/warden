import { execFileSync } from "node:child_process";
import type { Finding } from "../../model/finding.ts";
import type { Severity } from "../../model/severity.ts";
import type { DetectContext } from "../../detect/types.ts";
import type { AuditLog } from "../../audit/log.ts";
import { makeFinding } from "../../util/finding.ts";
import { maskSecrets } from "../../secret/mask.ts";

/**
 * Git geçmişi secret taraması (B1 genişletme). Bir secret HEAD'den silinmiş olsa bile
 * geçmiş commit'lerde durur ve iptal/rotasyon gerektirir — Gitleaks/TruffleHog'un ana katma
 * değeri budur. Read-only: yalnızca `git log -p` OKUR, hiçbir şey değiştirmez.
 *
 * FP'yi düşük tutmak için yalnızca YAPISAL, yüksek-güvenli desenler taranır (rastgele
 * "secret=..." atamaları değil).
 */

interface HistoryPattern {
  readonly id: string;
  readonly title: string;
  readonly severity: Severity;
  readonly re: RegExp;
}

const HISTORY_PATTERNS: readonly HistoryPattern[] = [
  { id: "aws-key", title: "AWS Access Key", severity: "P0", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: "private-key", title: "Private key bloğu", severity: "P0", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { id: "provider-token", title: "Sağlayıcı anahtarı", severity: "P0",
    re: /\b(xox[baprs]-[0-9A-Za-z-]{10,}|ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,}|sk_live_[0-9A-Za-z]{16,}|AIza[0-9A-Za-z_\-]{35}|glpat-[0-9A-Za-z_\-]{20}|npm_[0-9A-Za-z]{36}|SG\.[\w\-]{22}\.[\w\-]{43})\b/ },
  { id: "openai-key", title: "OpenAI/Anthropic anahtarı", severity: "P0", re: /\b(sk-ant-[0-9A-Za-z_\-]{20,}|sk-[A-Za-z0-9]{32,})\b/ },
];

/**
 * Belirgin yer-tutucu/örnek anahtarları eler (FP önleme — gitleaks allowlist mantığı).
 * Ör. AWS dokümantasyon anahtarı AKIAIOSFODNN7EXAMPLE veya AKIA1234567890ABCDEF fixture'ları.
 */
const PLACEHOLDER_SECRET = /EXAMPLE|1234567890|ABCDEF|0000000|1111111|XXXXXX|DEADBEEF|placeholder|dummy|sample|redacted|your[_-]/i;

function isPlaceholderSecret(token: string): boolean {
  return PLACEHOLDER_SECRET.test(token);
}

export interface HistoryHit {
  readonly commit: string;
  readonly patternId: string;
  readonly title: string;
  readonly severity: Severity;
  /** MASKELENMEMİŞ ham satır — çağıran maskeler. */
  readonly line: string;
}

/**
 * `git log -p` çıktısını ayrıştırır: eklenen (`+`) satırlarda yapısal secret arar.
 * Saf fonksiyon — test edilebilir. Aynı (commit, pattern, satır) tekrarları elenir.
 */
export function scanDiffForSecrets(logOutput: string): HistoryHit[] {
  const hits: HistoryHit[] = [];
  const seen = new Set<string>();
  let commit = "";
  for (const raw of logOutput.split(/\r?\n/)) {
    const cm = /^commit\s+([0-9a-f]{7,40})/.exec(raw);
    if (cm && cm[1]) {
      commit = cm[1].slice(0, 12);
      continue;
    }
    // Yalnızca eklenen satırlar (diff başlıklarını "+++" hariç tut).
    if (raw[0] !== "+" || raw.startsWith("+++")) continue;
    const added = raw.slice(1);
    for (const p of HISTORY_PATTERNS) {
      p.re.lastIndex = 0;
      const match = p.re.exec(added);
      if (!match) continue;
      if (isPlaceholderSecret(match[0])) continue; // belirgin dummy/örnek anahtar → atla
      const key = `${commit}|${p.id}|${added.trim()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({ commit, patternId: p.id, title: p.title, severity: p.severity, line: added.trim() });
    }
  }
  return hits;
}

/** History hit'lerini bulgulara çevirir (saf). Kanıt maskeli; fingerprint commit+desen ile kararlı. */
export function historyHitsToFindings(hits: readonly HistoryHit[]): Finding[] {
  return hits.map((h) =>
    makeFinding({
      id: `B1-history-secret:${h.commit}:${h.patternId}`,
      title: `Git geçmişinde secret: ${h.title}`,
      severity: h.severity,
      module: "B",
      check: "B1",
      category: "Secret",
      confidence: "high",
      evidence: [
        {
          type: "command",
          source: `git-history@${h.commit}`,
          location: h.commit,
          excerpt: maskSecrets(h.line.slice(0, 200)),
        },
      ],
      impact: "Secret geçmiş commit'te; HEAD'den silinse bile klonlarda/forklarda kalıcıdır ve sömürülebilir.",
      recommendation: "Secret'ı hemen iptal/rotasyon yap; git geçmişini temizle (git-filter-repo/BFG); secret manager'a taşı.",
      effort: "M",
      autoFixable: false,
      references: ["OWASP A07:2021", "gitleaks", "trufflehog"],
    }),
  );
}

/**
 * Best-effort git geçmişi taraması. `.git` yoksa veya git komutu başarısızsa boş döner
 * (asla fırlatmaz). Son `maxCommits` commit ile sınırlı (varsayılan 500).
 */
export function collectGitHistorySecrets(
  root: string,
  ctx: DetectContext,
  audit?: AuditLog,
  opts: { maxCommits?: number; maxBytes?: number } = {},
): { findings: Finding[]; ran: boolean } {
  if (!ctx.exists(".git")) return { findings: [], ran: false };
  const maxCommits = opts.maxCommits ?? 500;
  const maxBytes = opts.maxBytes ?? 8_000_000;
  try {
    audit?.command(`git log -p -n ${maxCommits} (secret taraması)`, root);
    const out = execFileSync(
      "git",
      ["log", "-p", "--no-color", "--no-merges", "-n", String(maxCommits), "--", "."],
      { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 60_000, maxBuffer: maxBytes },
    );
    return { findings: historyHitsToFindings(scanDiffForSecrets(out)), ran: true };
  } catch (err) {
    // maxBuffer aşımında bile kısmi stdout'u değerlendir.
    const e = err as { stdout?: string | Buffer };
    if (e?.stdout) {
      const text = typeof e.stdout === "string" ? e.stdout : e.stdout.toString("utf8");
      const hits = scanDiffForSecrets(text);
      if (hits.length > 0) return { findings: historyHitsToFindings(hits), ran: true };
    }
    audit?.warn("git geçmişi secret taraması atlandı (git yok/erişilemedi).");
    return { findings: [], ran: false };
  }
}

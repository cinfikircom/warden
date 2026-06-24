import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";
import { maskSecrets } from "../../secret/mask.ts";

/**
 * Modül AI — AI / LLM güvenliği (pasif, statik).
 * AI-1 Prompt Injection yüzeyi · AI-2 RAG/sistem-prompt sızıntısı · AI-3 LLM API key sızıntısı / endpoint exposure.
 * Yalnızca AI SDK kullanımı tespit edilirse koşar (gürültüyü önler).
 */

const CODE_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rb|java|cs|php)$/i;
const SKIP = /(^|\/)(node_modules|dist|build|warden-report|vendor)\/|\.min\.js$|(^|\/)(test|tests|__tests__|fixtures)\//i;
const AI_SDK = /\b(openai|@anthropic-ai\/sdk|anthropic|langchain|@langchain\/|llamaindex|cohere|@google\/generative-ai|ollama)\b/i;

// AI-3: gömülü LLM anahtarları
const KEY_PATTERNS: ReadonlyArray<{ re: RegExp; label: string }> = [
  { re: /\bsk-ant-[A-Za-z0-9_-]{20,}/, label: "Anthropic API key" },
  { re: /\bsk-(proj-)?[A-Za-z0-9]{20,}/, label: "OpenAI API key" },
  { re: /(OPENAI|ANTHROPIC|COHERE|GROQ)_API_KEY\s*[:=]\s*["'][^"'$]{12,}["']/i, label: "Hardcoded LLM API key" },
];

// AI-1: kullanıcı girdisinin prompt'a/mesaja birleştirilmesi
const PROMPT_CONCAT = /(prompt|messages|content|input|system|user)\s*[:=][^;\n]*(\+\s*(req\.|request\.|input|userInput|body|params|query|message)|\$\{(req\.|request\.|input|userInput|body|params|query|message))/i;
// AI-2: sistem prompt'unun loglanması / yanıta konması (sızıntı)
const SYSTEM_LEAK = /(systemPrompt|system_prompt|SYSTEM_PROMPT)[\s\S]{0,40}(console\.log|res\.(send|json)|print\()/i;

export interface AiData {
  readonly usesAi: boolean;
  readonly files: ReadonlyArray<{ path: string; content: string }>;
}

export function collectAiData(ctx: DetectContext): AiData {
  const candidates = ctx.find((p) => CODE_FILE.test(p) && !SKIP.test(p), { limit: 4000 });
  const files: Array<{ path: string; content: string }> = [];
  let usesAi = false;
  for (const f of candidates) {
    const content = ctx.readFile(f);
    if (content === null || content.length > 1_000_000) continue;
    if (AI_SDK.test(content)) usesAi = true;
    files.push({ path: f, content });
  }
  // package.json'da AI SDK bağımlılığı da sinyal.
  const pkg = ctx.readFile("package.json");
  if (pkg && AI_SDK.test(pkg)) usesAi = true;
  return { usesAi, files };
}

export function analyzeAi(data: AiData): Finding[] {
  if (!data.usesAi) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (f: Finding): void => {
    if (seen.has(f.fingerprint)) return;
    seen.add(f.fingerprint);
    findings.push(f);
  };

  for (const { path, content } of data.files) {
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i] as string;
      const loc = String(i + 1);

      for (const k of KEY_PATTERNS) {
        if (k.re.test(ln)) {
          push(makeFinding({
            id: `AI-3-key:${path}:${i + 1}`, title: `Gömülü LLM API anahtarı (${k.label})`, severity: "P0",
            module: "AI", check: "AI-3", category: "AI Secret Exposure", confidence: "high",
            evidence: [{ type: "file", source: path, location: loc, excerpt: maskSecrets(ln.trim().slice(0, 160)) }],
            impact: "Sızan LLM anahtarı maliyet/suistimal ve veri erişimi demektir.",
            recommendation: "Anahtarı iptal/rotasyon; env/secret manager'dan oku; koddan kaldır.",
            effort: "S", autoFixable: false, references: ["OWASP LLM02", "OWASP A07:2021"],
          }));
        }
      }

      if (PROMPT_CONCAT.test(ln)) {
        push(makeFinding({
          id: `AI-1-prompt-injection:${path}:${i + 1}`, title: "Prompt injection yüzeyi: kullanıcı girdisi doğrudan prompt'a birleştiriliyor", severity: "P1",
          module: "AI", check: "AI-1", category: "Prompt Injection", confidence: "low",
          evidence: [{ type: "file", source: path, location: loc, excerpt: ln.trim().slice(0, 160) }],
          impact: "Sanitize edilmemiş girdi sistem talimatlarını geçersiz kılabilir (prompt injection).",
          recommendation: "Girdiyi ayır (kullanıcı rolü), sınırla/escape et; sistem talimatını ayrı tut; çıktı doğrula.",
          effort: "M", autoFixable: false, references: ["OWASP LLM01"],
        }));
      }

      if (SYSTEM_LEAK.test(ln)) {
        push(makeFinding({
          id: `AI-2-system-leak:${path}:${i + 1}`, title: "Sistem prompt'u loglanıyor/yanıta konuyor (sızıntı)", severity: "P2",
          module: "AI", check: "AI-2", category: "RAG/Prompt Leakage", confidence: "low",
          evidence: [{ type: "file", source: path, location: loc, excerpt: ln.trim().slice(0, 160) }],
          impact: "Sistem prompt'u/RAG içeriği sızarsa savunma talimatları ve gizli bağlam açığa çıkar.",
          recommendation: "Sistem prompt'unu loglama/istemciye gönderme; gizli bağlamı ayır.",
          effort: "S", autoFixable: false, references: ["OWASP LLM06"],
        }));
      }
    }
  }
  return findings;
}

export const aiModule: WardenModule = {
  id: "AI",
  title: "AI / LLM Güvenliği",
  active: false,
  applicable(ctx: ScanContext) {
    return collectAiData(ctx.fs).usesAi;
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const findings = analyzeAi(collectAiData(ctx.fs));
    ctx.audit.info(`AI: ${findings.length} bulgu.`);
    return { findings };
  },
};

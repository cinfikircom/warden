import type { Finding } from "../../model/finding.ts";
import type { ParityLayer } from "../../model/parity.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

export interface ExternalData {
  /** {dosya, satır, url} — prod config'te yerel/geçici görünen webhook URL'leri. */
  readonly localWebhooks: ReadonlyArray<{ file: string; line: number; url: string }>;
  /** Statik olarak herhangi bir dış-bağımlılık sinyali görüldü mü. */
  readonly assessed: boolean;
}

const LOCAL_HOST_URL = /(https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|[a-z0-9-]+\.ngrok[a-z.-]*|[a-z0-9-]+\.trycloudflare\.com))/i;
const WEBHOOK_KEY = /(webhook|callback|redirect_uri|notify_url)/i;

export function collectExternalData(ctx: DetectContext): ExternalData {
  const candidates = ctx.find(
    (p) => /\.env(\.|$)|\.(ya?ml|json|toml|ini|conf)$/i.test(p) && !p.includes("warden-report"),
    { limit: 400 },
  );
  const localWebhooks: Array<{ file: string; line: number; url: string }> = [];
  let assessed = false;
  for (const f of candidates) {
    const text = ctx.readFile(f);
    if (!text) continue;
    assessed = true;
    text.split(/\r?\n/).forEach((ln, i) => {
      if (WEBHOOK_KEY.test(ln)) {
        const m = LOCAL_HOST_URL.exec(ln);
        if (m) localWebhooks.push({ file: f, line: i + 1, url: m[1] as string });
      }
    });
  }
  return { localWebhooks, assessed };
}

/** A6 — saf analiz. Çoğu (OAuth scope, key geçerliliği) canlı doğrulama ister → kısmen unknown. */
export function analyzeExternal(data: ExternalData): { findings: Finding[]; layer: ParityLayer } {
  const findings: Finding[] = [];
  for (const w of data.localWebhooks) {
    findings.push(
      makeFinding({
        id: `A6-local-webhook:${w.file}:${w.line}`,
        title: `Webhook/callback yerel veya geçici host'a bakıyor: ${w.url}`,
        severity: "P2",
        module: "A",
        check: "A6",
        category: "External Dependencies",
        confidence: "medium",
        evidence: [{ type: "config", source: w.file, location: String(w.line), excerpt: w.url }],
        impact: "Prod'da 3rd-party geri çağrıları erişilemez/geçici adrese gider; olaylar kaybolur.",
        recommendation: "Kalıcı public prod URL kullan; ortam başına webhook URL'sini ayır.",
        effort: "S",
        autoFixable: false,
      }),
    );
  }

  if (!data.assessed) {
    return {
      findings,
      layer: { code: "A6", name: "External Dependencies", status: "unknown", score: null, note: "Config dosyası bulunamadı.", findingIds: [] },
    };
  }
  let score = 10;
  for (const f of findings) score -= f.severity === "P2" ? 1 : 2.5;
  const status = findings.length > 0 ? "warn" : "ok";
  return {
    findings,
    layer: {
      code: "A6",
      name: "External Dependencies",
      status,
      score: Math.max(0, Math.round(score * 10) / 10),
      note:
        findings.length === 0
          ? "Statik webhook kontrolü temiz (OAuth/key geçerliliği canlı doğrulama ister)."
          : `${findings.length} dış bağımlılık bulgusu.`,
      findingIds: findings.map((f) => f.id),
    },
  };
}

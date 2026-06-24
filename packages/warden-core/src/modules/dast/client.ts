import type { AuthzResult } from "../../authz/gate.ts";
import { isTargetAuthorized } from "../../authz/gate.ts";
import type { AuditLog } from "../../audit/log.ts";

/**
 * Korumalı HTTP istemcisi (Modül C / DAST). §2 ilkelerini KOD SEVİYESİNDE zorlar:
 *  - YALNIZCA allow-list host'larına istek (her istekte yeniden doğrulanır)
 *  - YALNIZCA GET/HEAD (non-destructive; body/payload yok)
 *  - rate-limit (maxRequestsPerSecond) + toplam istek tavanı (maxTotalRequests)
 *  - redirect'leri TAKİP ETMEZ (off-list host'a sıçramayı önler)
 *  - her istek audit-log'a yazılır
 * DoS/brute-force/exploit YOK.
 */

export interface ProbeResponse {
  readonly url: string;
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly setCookies: readonly string[];
  /** İlk ~2KB gövde (kanıt için; maskeleme rapor katmanında). */
  readonly body: string;
}

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export class GuardedHttpClient {
  readonly #authz: AuthzResult;
  readonly #audit: AuditLog;
  readonly #fetch: FetchLike;
  #total = 0;
  #lastAt = 0;

  constructor(authz: AuthzResult, audit: AuditLog, fetchImpl?: FetchLike) {
    this.#authz = authz;
    this.#audit = audit;
    this.#fetch = fetchImpl ?? ((u, i) => fetch(u, i));
  }

  get totalRequests(): number {
    return this.#total;
  }

  /** Bir GET probe'u. İzin verilmeyen/sınır aşan durumda HİÇ istek atmadan null döner. */
  async get(rawUrl: string): Promise<ProbeResponse | null> {
    // 0) Mod kontrolü — aktif değilse asla istek yok.
    if (this.#authz.mode !== "active") {
      this.#audit.warn(`DAST isteği reddedildi: mod aktif değil (${rawUrl}).`);
      return null;
    }

    let host: string;
    try {
      host = new URL(rawUrl).hostname;
    } catch {
      this.#audit.warn(`Geçersiz URL, atlandı: ${rawUrl}`);
      return null;
    }

    // 1) Allow-list — her istekte yeniden doğrula.
    if (!isTargetAuthorized(this.#authz, host)) {
      this.#audit.warn(`ENGELLENDİ (allow-list dışı host): ${host} — istek gönderilmedi.`);
      return null;
    }

    // 2) Toplam istek tavanı.
    if (this.#total >= this.#authz.limits.maxTotalRequests) {
      this.#audit.warn(`İstek tavanı doldu (${this.#authz.limits.maxTotalRequests}); ${rawUrl} atlandı.`);
      return null;
    }

    // 3) Rate-limit (DoS önler).
    const minInterval = 1000 / Math.max(0.1, this.#authz.limits.maxRequestsPerSecond);
    const now = Date.now();
    const wait = this.#lastAt + minInterval - now;
    if (wait > 0) await sleep(wait);
    this.#lastAt = Date.now();

    this.#total++;
    this.#audit.command(`GET ${rawUrl}`, host);

    // 4) Non-destructive istek: GET, redirect takip etme, kısa timeout.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const res = await this.#fetch(rawUrl, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: { "user-agent": "Warden/0.4 (+read-only security audit)" },
      });
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        headers[k.toLowerCase()] = v;
      });
      const setCookies = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
      let body = "";
      try {
        body = (await res.text()).slice(0, 2048);
      } catch {
        /* gövde okunamadı */
      }
      return { url: rawUrl, status: res.status, headers, setCookies, body };
    } catch (err) {
      this.#audit.warn(`İstek başarısız (${rawUrl}): ${String(err)}`);
      return { url: rawUrl, status: 0, headers: {}, setCookies: [], body: "" };
    } finally {
      clearTimeout(timer);
    }
  }
}

import type { StackDetector } from "../types.ts";

const COMPOSE_FILES = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"];

/** Docker / Compose — A3/A4 katmanlarının girdisi. */
export const dockerDetector: StackDetector = {
  id: "docker",
  priority: 70,
  async detect(ctx) {
    const composePath = COMPOSE_FILES.find((f) => ctx.exists(f));
    const dockerfiles = ctx.find((p) => /(^|\/)Dockerfile([.-].+)?$/.test(p), { limit: 50 });
    if (!composePath && dockerfiles.length === 0) return null;
    return {
      containerized: true,
      signals: { composePath: composePath ?? null, dockerfiles },
    };
  },
};

/**
 * Cloudflare — nokta 6: ŞİMDİLİK YALNIZCA TESPİT (adaptör Faz 6+).
 * wrangler.toml / cloudflare.toml / workers / pages / tunnel sinyallerini keşfeder.
 */
export const cloudflareDetector: StackDetector = {
  id: "cloudflare",
  priority: 60,
  async detect(ctx) {
    const wrangler = ["wrangler.toml", "wrangler.jsonc", "wrangler.json"].find((f) => ctx.exists(f)) ?? null;
    const cloudflareToml = ctx.exists("cloudflare.toml");
    const tunnel =
      ctx.exists(".cloudflared/config.yml") ||
      ctx.find((p) => /(^|\/)cloudflared.*\.(yml|yaml)$/.test(p), { limit: 10 }).length > 0;

    const wranglerText = wrangler ? (ctx.readFile(wrangler) ?? "") : "";
    const isPages = /pages_build_output_dir|\[\[?\s*pages/i.test(wranglerText) || ctx.exists("functions");
    const isWorkers = wrangler !== null && /main\s*=|\[build\]|compatibility_date/i.test(wranglerText);

    if (!wrangler && !cloudflareToml && !tunnel) return null;

    return {
      cloud: ["cloudflare"],
      signals: {
        wrangler,
        cloudflareToml,
        tunnel,
        pages: isPages,
        workers: isWorkers,
        note: "Cloudflare yalnızca TESPİT edildi; kontroller Faz 6+ (CLOUD-CF).",
      },
    };
  },
};

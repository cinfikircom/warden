/**
 * COMBINED PROFILE (Phase 3) — one knight, the whole security picture.
 * =========================================================================
 * Merges both armor sets into a single posture:
 *   • Runtime defense (bot/abuse layers from posture.js)
 *   • Code scan (Warden scan dimensions from posture-warden.js)
 * The knight now reflects your COMPLETE security posture — runtime + codebase — in one panel,
 * one measured score. Feed it via /api/combined/posture (server merges both sources).
 * =========================================================================
 */
import { POSTURE } from "./posture.js";
import { WARDEN_POSTURE } from "./posture-warden.js";

const tag = (layers, group) => layers.map(l => ({ ...l, group }));

export const COMBINED_POSTURE = {
  base: POSTURE.base,
  ranks: POSTURE.ranks,
  layers: [
    ...tag(POSTURE.layers, "🛡️ Çalışma-zamanı savunması (bot & kötüye kullanım)"),
    ...tag(WARDEN_POSTURE.layers, "🔍 Kod taraması (Warden)"),
  ],
  relics: POSTURE.relics || [],
  metrics: {}, // filled by /api/combined/posture
};

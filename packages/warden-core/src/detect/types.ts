import type { StackInfo } from "../model/module.ts";

/**
 * Stack Detector eklenti sistemi (nokta 1). Her stack için bir dedektör; ileride
 * PHP/.NET/Go eklemek = yeni bir dosya. Dedektörler READ-ONLY'dir.
 */
export interface DetectContext {
  readonly projectRoot: string;
  /** Yol projeye göredir. Dosya yoksa null döner (asla fırlatmaz). */
  readFile(relPath: string): string | null;
  exists(relPath: string): boolean;
  /** Verilen desenle eşleşen dosyaları döndürür (node_modules/.git hariç, derinlik sınırlı). */
  find(predicate: (relPath: string) => boolean, opts?: { maxDepth?: number; limit?: number }): string[];
}

/** Bir dedektörün katkısı; registry bunları birleştirir. */
export interface DetectionResult {
  readonly languages?: readonly string[];
  readonly frameworks?: readonly string[];
  readonly orm?: readonly string[];
  readonly containerized?: boolean;
  readonly cloud?: readonly string[];
  /** Dedektöre özel ham sinyaller (bulunan dosya yolları vb.). raw[detector.id] altına yazılır. */
  readonly signals?: Readonly<Record<string, unknown>>;
}

export interface StackDetector {
  readonly id: string;
  /** Yüksek öncelik önce çalışır; çakışmada öncelikli kazanır. */
  readonly priority: number;
  detect(ctx: DetectContext): Promise<DetectionResult | null>;
}

export type { StackInfo };

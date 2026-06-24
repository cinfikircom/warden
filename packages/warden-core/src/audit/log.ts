import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { maskSecrets } from "../secret/mask.ts";

/**
 * Audit log (iş emri §2.5): Warden'in çalıştırdığı/denediği her komut ve mod geçişi
 * `warden-report/warden-run.log`'a yazılır (şeffaflık + yetki kanıtı). Tüm satırlar
 * secret-maskeli yazılır.
 */
export class AuditLog {
  readonly #path: string;

  constructor(path: string) {
    this.#path = path;
    mkdirSync(dirname(path), { recursive: true });
  }

  #write(kind: string, message: string): void {
    // Date.now() çağrısı harness kısıtı nedeniyle değil, gerçek çalışmada zaman damgası gerek.
    const ts = new Date().toISOString();
    const line = `${ts} [${kind}] ${maskSecrets(message)}\n`;
    appendFileSync(this.#path, line, "utf8");
  }

  /** Bilgilendirme satırı (mod, faz, karar). */
  info(message: string): void {
    this.#write("INFO", message);
  }

  /** Yetki kapısı kararı. */
  authz(message: string): void {
    this.#write("AUTHZ", message);
  }

  /** Çalıştırılan bir komut (aktif test dahil). */
  command(command: string, target?: string): void {
    this.#write("CMD", target ? `${command}  → target=${target}` : command);
  }

  /** Uyarı. */
  warn(message: string): void {
    this.#write("WARN", message);
  }

  get path(): string {
    return this.#path;
  }
}

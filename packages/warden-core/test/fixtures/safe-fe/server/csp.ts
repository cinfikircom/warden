// FP muhafızı — bu dosya HİÇ bulgu üretmemeli.
// nonce tabanlı CSP; unsafe-inline/unsafe-eval yok → FE-2 tetiklenmemeli.
import helmet from "helmet";

export function security(nonce: string) {
  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'"],
        styleSrc: ["'self'"],
      },
    },
  });
}

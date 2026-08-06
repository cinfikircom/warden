// Bilerek açıklı fixture — yalnızca test amaçlı. Üretimde KULLANMA.
//
// FE-2 REGRESYON TESTİ: CSP direktifi ile 'unsafe-inline' FARKLI SATIRLARDA.
// Eski satır-bazlı kural (`/Content-Security-Policy[\s\S]{0,120}?(unsafe-inline)/`) bunu
// yapısal olarak KAÇIRIYORDU — tarayıcı satır satır test ediyor, `[\s\S]` hiçbir zaman
// satır sınırını aşamıyordu. Bu dosya tek satıra indirgenmemeli.
import helmet from "helmet";

export const security = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
});

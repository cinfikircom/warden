import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";
import { maskSecrets } from "../../secret/mask.ts";

/**
 * Modül PAY — Ödeme Güvenliği & Güvenilirliği (pasif, statik).
 * =========================================================================
 * Para söz konusu olduğu için en yüksek riskli akış. Çoğu tarayıcının atladığı, ödeme-akışına
 * ÖZGÜ hataları arar (jenerik secret/PCI kontrolleri B/D'de kalır):
 *
 *   Güvenlik:
 *     PAY-1  Ödeme secret anahtarı sızıntısı (sk_live_/whsec_ … özellikle client bundle'da → felaket)
 *     PAY-2  Webhook imza doğrulaması YOK → saldırgan "ödeme başarılı" olayını taklit eder
 *     PAY-3  Tutar istemciden geliyor (price tampering) → 1000₺'lik ürüne 1₺ ödenir
 *     PAY-5  Kart verisi (PAN/CVV) sunucuda işleniyor/loglanıyor (PCI ihlali)
 *     PAY-12 3DS/SCA desteklemeyen legacy Charges API → AB kartlarında red / PSD2 ihlali
 *     PAY-13 İade tutarı istemciden (over-refund) → orijinalden fazla/başkasının ödemesi iade
 *
 *   Güvenilirlik (para kaybı / "boşa düşen ödeme"):
 *     PAY-4  Charge oluşturma idempotency-key'siz → retry'da çift çekim
 *     PAY-7  Mutabakat (reconciliation) job'ı YOK → sağlayıcı ↔ DB tutarsızlığı sessizce birikir
 *     PAY-8  Webhook olay tekilleştirme (dedup) YOK → sağlayıcı retry'ında çift teslim/çift iade
 *     PAY-9  Kesinti/orphan ödeme koruması YOK → çekilmiş ama karşılığı verilmemiş ödeme (para boşa)
 *     PAY-10 Başarısız/asenkron ödeme olayı işlenmiyor → para limboda, iade/başarısızlık kaçar
 *     PAY-11 Abonelik var ama dunning (başarısız yenileme) YOK → gelir sızıntısı / bedava erişim
 *
 * Yalnızca bir ödeme entegrasyonu tespit edilirse koşar (gürültüyü önler). Yokluk-temelli
 * kontroller (PAY-7/8/9/10) heuristiktir → düşük/orta güven, açıkça işaretlenir; yanlış-pozitif
 * ise `.warden-ignore.yml` ile bastırılabilir.
 * =========================================================================
 */

const CODE_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rb|java|cs|php)$/i;
const SKIP = /(^|\/)(node_modules|dist|build|\.next|warden-report|vendor|coverage)\/|\.min\.js$|(^|\/)(test|tests|__tests__|fixtures|__mocks__)\//i;

// --- Sağlayıcı tespiti (uygulanabilirlik kapısı) ---
// Bağımlılık adları (güvenilir sinyal): global + Türkiye sağlayıcıları.
const PAY_DEP = /\b(stripe|braintree|paypal-rest-sdk|@paypal\/checkout-server-sdk|@paypal\/paypal-js|adyen|@adyen\/api-library|razorpay|mollie|@mollie\/api-client|checkout-sdk-node|@paddle\/paddle-node-sdk|klarna|coinbase-commerce-node|dwolla-v2|iyzipay|craftgate|node-sipay|payu|@square\/web-sdk|squareup)\b/i;
// Kod-içi API şekilleri (Stripe/PayPal/iyzico/Adyen/Razorpay…).
const PAY_CODE = /\bnew\s+Stripe\b|\bStripe\s*\(|stripe\.(paymentIntents|charges|checkout|webhooks|refunds|subscriptions|paymentMethods)|paymentIntents\.create|\bIyzipay\b|new\s+Iyzipay|braintree\.(gateway|Transaction)|new\s+Adyen|\bAdyen\s*\(|new\s+Razorpay|\brazorpay\b|@mollie|createPaymentIntent|\bPaymentIntent\b|checkout\.sessions\.create|iyzico|craftgate/i;
// Ödeme secret/anahtar desenleri (kod-içi).
const KEY_LIVE = /\b(sk_live_[A-Za-z0-9]{8,}|rk_live_[A-Za-z0-9]{8,}|whsec_[A-Za-z0-9]{8,})/;
const KEY_TEST = /\bsk_test_[A-Za-z0-9]{8,}/;
const KEY_ENV_HARDCODE = /\b(STRIPE_SECRET_KEY|STRIPE_WEBHOOK_SECRET|PAYPAL_CLIENT_SECRET|PAYPAL_SECRET|IYZICO_SECRET_KEY|IYZIPAY_SECRET|ADYEN_API_KEY|RAZORPAY_KEY_SECRET|MOLLIE_API_KEY|BRAINTREE_PRIVATE_KEY)\s*[:=]\s*["'][^"'$\s]{8,}["']/i;

// --- Güvenlik desenleri ---
// PAY-3: tutar/fiyat doğrudan istemci girdisinden.
const AMOUNT_FROM_CLIENT = /\b(amount|price|total|tutar|unit_amount|amount_total|fiyat|paidPrice)\b\s*[:=]\s*(req\.(body|query|params)|request\.(body|query|args|POST)|ctx\.request\.body|\$_(POST|GET|REQUEST)|params\[|body\.[A-Za-z_])/i;
// PAY-5: kart verisi loglama/sunucuda tutma.
const CARD_LOG = /(console\.(log|info|debug|warn|error)|logger?\.(info|debug|warn|error|log)|print\(|printf|fmt\.Print|System\.out)\s*[\s\S]{0,80}(card_?number|cardnumber|\bcardno\b|\bpan\b|\bcvv2?\b|\bcvc2?\b|card_?verification|primary_?account_?number)/i;
// PAY-4: charge/intent/refund oluşturma (idempotency dosyada aranır).
const CHARGE_CREATE = /(paymentIntents|charges|refunds|checkout\.sessions|payment_intents|paymentRequest|\.charge|createPayment|iyzipay\.\w+\.create|Transaction\.sale|payments\.create)\s*\.?\s*(create|sale|__call)?\s*\(/;
// GERÇEK idempotency kullanımını ara (option/header), yorumdaki "idempotency" kelimesini değil —
// aksi halde "no idempotency key" gibi bir yorum tespiti sahte-bastırır (false negative).
const IDEMPOTENT = /idempotency[_-]?key|idempotencyKey|PayPal-Request-Id|X-Idempotency|Idempotency-Key/i;

// --- Webhook desenleri ---
const WEBHOOK_HINT = /webhook|stripe-signature|paypal-transmission-(id|sig|time)|razorpay-signature|x-iyzico-signature|checkout-signature|x-cc-webhook-signature|payment.*callback|callback.*payment/i;
const VERIFY_SIG = /constructEvent|webhooks?\.(verify|constructEvent)|verify(Webhook|Signature|Header|Notification)|checkSignature|validateSignature|compareSignature|timingSafeEqual|hmac_?compare|verifyRazorpaySignature/i;
const DEDUP_SIG = /(event\.id|eventId|event_id|\bevt\.id\b)|already.?(processed|handled)|processed_?events?|dedup|seenEvents?|idempotency[_-]?key|idempotencyKey|hasProcessed|isProcessed|INSERT[\s\S]{0,40}unique/i;
const FAILURE_EVENT = /payment_intent\.payment_failed|charge\.failed|charge\.refunded|charge\.dispute|checkout\.session\.async_payment_failed|payment_failed|\.declined\b|refunded|chargeback|dispute|canceled|cancelled|expired|voided/i;

// --- Güvenilirlik (proje düzeyi, yokluk-temelli) ---
const RECONCILE_SIG = /reconcil|mutabakat|settlement[\s\S]{0,40}(match|compare|verify|reconcile)|payout[\s\S]{0,40}(match|reconcile)|sync[\s\S]{0,20}(charges|payments|orders|balance)|verifyCharges|compareLedger|balanceTransactions\.list[\s\S]{0,120}(compare|match|reconcile)/i;
const PENDING_STATE = /\b(status|state|payment_?status|paymentStatus|odeme_?durumu)\b[\s\S]{0,20}["'](pending|awaiting|processing|authorized|created|initiated|bekliyor|beklemede)["']|enum[\s\S]{0,60}(PENDING|AUTHORIZED|CAPTURED)/i;
const SWEEP_SIG = /(stale|orphan|uncaptured|expired|pending)[\s\S]{0,30}(payment|charge|intent|order)|sweep|cleanupPending|expirePending|reconcilePending|cancelStale/i;

// --- Abonelik & dunning (PAY-11) ---
const SUB_SIG = /subscriptions?\.create|customer\.subscription|createSubscription|\brecurring\b|billing_cycle|\bsubscription\b|\babonelik\b/i;
const DUNNING_SIG = /invoice\.payment_failed|payment_action_required|past_due|dunning|customer\.subscription\.deleted|grace.?period|retry[\s\S]{0,20}(payment|invoice|charge)|mark[\s\S]{0,20}past_due|smart.?retries?/i;
// --- 3DS / SCA (PAY-12): legacy Charges API SCA/3DS desteklemez ---
const LEGACY_CHARGE = /\bcharges\.create\s*\(|\bCharge\.create\s*\(/i;
// --- Refund (PAY-13) ---
const REFUND_CREATE = /\brefunds\.create\s*\(|\bcreateRefund\b|\bRefund\.create\b|\.refund\s*\(/i;

export interface PayFile {
  readonly path: string;
  readonly content: string;
  /** İstemciye gidebilecek dosya mı (client bundle / public / "use client"). */
  readonly isClient: boolean;
}
export interface PayData {
  readonly usesPayments: boolean;
  readonly providers: readonly string[];
  readonly files: readonly PayFile[];
  /** Ödeme-bağlamlı dosyalarda mutabakat sinyali bulundu mu. */
  readonly hasReconciliation: boolean;
  /** Kesinti/orphan ödeme süpürme (sweep) sinyali bulundu mu. */
  readonly hasSweep: boolean;
  /** Ara "pending/authorized" ödeme durumu persist ediliyor mu. */
  readonly hasPendingState: boolean;
  /** Abonelik (recurring) kullanılıyor mu. */
  readonly usesSubscriptions: boolean;
  /** Başarısız yenileme / dunning işleme sinyali bulundu mu. */
  readonly hasDunning: boolean;
}

const CLIENT_HINT = /(^|\/)(public|static|assets|dist|build|www|client|frontend|components|pages|app)\//i;

function readDeps(ctx: DetectContext): string {
  return [
    ctx.readFile("package.json"),
    ctx.readFile("requirements.txt"),
    ctx.readFile("pyproject.toml"),
    ctx.readFile("composer.json"),
    ctx.readFile("go.mod"),
    ctx.readFile("Gemfile"),
    ctx.readFile("pom.xml"),
  ].filter(Boolean).join("\n");
}

export function collectPayData(ctx: DetectContext): PayData {
  const deps = readDeps(ctx);
  const providers = new Set<string>();
  for (const m of deps.matchAll(new RegExp(PAY_DEP, "gi"))) if (m[1]) providers.add(m[1].toLowerCase());

  const candidates = ctx.find((p) => CODE_FILE.test(p) && !SKIP.test(p), { limit: 5000 });
  const files: PayFile[] = [];
  let usesPayments = PAY_DEP.test(deps);
  let hasReconciliation = false;
  let hasSweep = false;
  let hasPendingState = false;
  let usesSubscriptions = false;
  let hasDunning = false;

  for (const f of candidates) {
    const content = ctx.readFile(f);
    if (content === null || content.length > 1_000_000) continue;
    const isPay = PAY_CODE.test(content) || KEY_LIVE.test(content) || KEY_TEST.test(content) || KEY_ENV_HARDCODE.test(content);
    // Mutabakat/sweep/pending/abonelik sinyallerini yalnızca ödeme-bağlamı olan projede ara (gürültüyü azalt).
    if (RECONCILE_SIG.test(content)) hasReconciliation = true;
    if (SWEEP_SIG.test(content)) hasSweep = true;
    if (PENDING_STATE.test(content)) hasPendingState = true;
    if (SUB_SIG.test(content)) usesSubscriptions = true;
    if (DUNNING_SIG.test(content)) hasDunning = true;
    if (isPay) {
      usesPayments = true;
      const isClient = CLIENT_HINT.test(f) || /["']use client["']/.test(content) || /\.(jsx|tsx)$/i.test(f);
      files.push({ path: f, content, isClient });
    }
  }
  return { usesPayments, providers: [...providers], files, hasReconciliation, hasSweep, hasPendingState, usesSubscriptions, hasDunning };
}

export function analyzePay(data: PayData): Finding[] {
  if (!data.usesPayments) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (f: Finding): void => {
    if (seen.has(f.fingerprint)) return;
    seen.add(f.fingerprint);
    findings.push(f);
  };

  let anyWebhookHandler = false;

  // --- Dosya + satır bazlı kontroller ---
  for (const { path, content, isClient } of data.files) {
    const lines = content.split(/\r?\n/);
    const fileHasWebhook = WEBHOOK_HINT.test(content);
    const fileVerifies = VERIFY_SIG.test(content);
    const fileDedups = DEDUP_SIG.test(content);
    const fileHandlesFailure = FAILURE_EVENT.test(content);
    const fileHasCharge = CHARGE_CREATE.test(content);
    const fileIdempotent = IDEMPOTENT.test(content);
    const fileHasRefund = REFUND_CREATE.test(content);

    // PAY-2 / PAY-8 / PAY-10 — webhook handler bir kez (dosya düzeyi).
    if (fileHasWebhook && (PAY_CODE.test(content) || /signature/i.test(content))) {
      anyWebhookHandler = true;
      if (!fileVerifies) {
        push(makeFinding({
          id: `PAY-2-webhook-unverified:${path}`, title: "Ödeme webhook'u imza doğrulaması olmadan işleniyor",
          severity: "P0", module: "PAY", check: "PAY-2", category: "Payment Webhook Integrity", confidence: "medium",
          evidence: [{ type: "file", source: path, excerpt: "webhook handler var, imza doğrulama (constructEvent/verifySignature) yok" }],
          impact: "İmza doğrulanmadan bir saldırgan sahte 'ödeme başarılı' olayı gönderip ödemeden ürün/hak elde edebilir.",
          recommendation: "Sağlayıcının imza doğrulamasını uygula (Stripe: webhooks.constructEvent ham gövde + Stripe-Signature + endpoint secret; benzeri PayPal/iyzico/Adyen HMAC). Doğrulanmayan olayı reddet.",
          effort: "M", autoFixable: false, references: ["OWASP A08:2021", "CWE-345"],
        }));
      }
      if (!fileDedups) {
        push(makeFinding({
          id: `PAY-8-webhook-no-dedup:${path}`, title: "Webhook olayları tekilleştirilmiyor (dedup yok) → çift teslim/iade riski",
          severity: "P1", module: "PAY", check: "PAY-8", category: "Payment Reliability", confidence: "low",
          evidence: [{ type: "file", source: path, excerpt: "webhook handler var, event.id ile tekilleştirme/işlendi-kontrolü yok" }],
          impact: "Sağlayıcılar webhook'u yeniden dener (retry). Aynı olay iki kez işlenirse sipariş iki kez teslim edilir ya da iki kez iade yapılır — para kaybı.",
          recommendation: "Her olayın id'sini kalıcı sakla; işlemeden önce 'zaten işlendi mi' kontrolü yap (idempotent tüketim / unique index).",
          effort: "M", autoFixable: false, references: ["Stripe: idempotent webhooks", "CWE-696"],
        }));
      }
      if (!fileHandlesFailure) {
        push(makeFinding({
          id: `PAY-10-webhook-no-failure:${path}`, title: "Başarısız/asenkron ödeme olayları işlenmiyor",
          severity: "P2", module: "PAY", check: "PAY-10", category: "Payment Reliability", confidence: "low",
          evidence: [{ type: "file", source: path, excerpt: "webhook yalnızca başarı akışını işliyor; payment_failed/refunded/dispute/expired yok" }],
          impact: "SEPA/banka/3DS gibi asenkron ödemeler ya da başarısızlık/iade/chargeback olayları işlenmezse ödeme limboda kalır, mutabakat bozulur.",
          recommendation: "payment_intent.payment_failed, charge.refunded, dispute, checkout async_payment_failed vb. olayları da işle; durumu buna göre güncelle.",
          effort: "M", autoFixable: false, references: ["Stripe: handle events"],
        }));
      }
    }

    // PAY-4 — charge oluşturma idempotency-key'siz (dosya düzeyi).
    if (fileHasCharge && !fileIdempotent) {
      push(makeFinding({
        id: `PAY-4-no-idempotency:${path}`, title: "Ödeme oluşturma idempotency anahtarı olmadan çağrılıyor",
        severity: "P1", module: "PAY", check: "PAY-4", category: "Payment Reliability", confidence: "low",
        evidence: [{ type: "file", source: path, excerpt: "charge/paymentIntent/refund create çağrısı var, idempotencyKey yok" }],
        impact: "Ağ kesintisi/retry'da aynı çağrı iki kez ulaşırsa müşteri iki kez çekilir. Belirsiz durumda (timeout) çekim yapılıp yapılmadığı bilinemez.",
        recommendation: "create çağrısına stabil bir idempotencyKey ver (ör. sipariş/intent id). Timeout'ta aynı key ile güvenle tekrar dene.",
        effort: "S", autoFixable: false, references: ["Stripe: idempotent requests"],
      }));
    }

    // PAY-12 — 3DS/SCA: legacy Charges API SCA/3DS desteklemez (dosya düzeyi).
    if (LEGACY_CHARGE.test(content)) {
      const li = lines.findIndex((l) => LEGACY_CHARGE.test(l));
      push(makeFinding({
        id: `PAY-12-no-sca:${path}`, title: "3DS/SCA desteklemeyen legacy Charges API kullanılıyor",
        severity: "P1", module: "PAY", check: "PAY-12", category: "Payment SCA / 3DS", confidence: "medium",
        evidence: [{ type: "file", source: path, ...(li >= 0 ? { location: String(li + 1) } : {}), excerpt: "charges.create (legacy) — Strong Customer Authentication (3DS) akışını desteklemez" }],
        impact: "Eski Charges API 3DS/SCA akışını yürütemez; AB kartlarında ödeme reddedilir veya PSD2/SCA ihlali oluşur, kimlik-doğrulamasız işlemler chargeback riskini artırır.",
        recommendation: "PaymentIntents API'ye geç (otomatik SCA/3DS). Gerekiyorsa 3DS'i zorunlu kıl (ör. request_three_d_secure: 'any'); off-session akışlarında authentication_required'ı ele al.",
        effort: "M", autoFixable: false, references: ["PSD2 SCA", "Stripe: PaymentIntents & 3DS"],
      }));
    }

    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i] as string;
      const loc = String(i + 1);

      // PAY-1 — ödeme secret anahtarı sızıntısı.
      const liveHit = KEY_LIVE.test(ln);
      const testHit = !liveHit && KEY_TEST.test(ln);
      const envHit = !liveHit && !testHit && KEY_ENV_HARDCODE.test(ln);
      if (liveHit || testHit || envHit) {
        const clientPay0 = isClient && (liveHit || envHit);
        push(makeFinding({
          id: `PAY-1-key:${path}:${i + 1}`,
          title: clientPay0
            ? "CANLI ödeme secret anahtarı istemci/paylaşılan koda gömülü (felaket)"
            : testHit ? "Test ödeme anahtarı koda gömülü (commit'lenmemeli)" : "Ödeme secret anahtarı koda gömülü",
          severity: liveHit ? "P0" : envHit ? "P0" : "P2",
          module: "PAY", check: "PAY-1", category: "Payment Secret Exposure", confidence: "high",
          evidence: [{ type: "file", source: path, location: loc, excerpt: maskSecrets(ln.trim().slice(0, 160)) }],
          impact: clientPay0
            ? "İstemciye giden canlı secret anahtar tüm ödeme hesabını ele geçirtir (para çekme, iade, veri)."
            : "Sızan ödeme anahtarı hesabın kötüye kullanımına (yetkisiz çekim/iade) yol açar.",
          recommendation: "Anahtarı DERHAL iptal/rotasyon; env/secret manager'dan oku; koddan ve git geçmişinden kaldır; asla istemciye gönderme (yalnız publishable/pk_ istemcide olabilir).",
          effort: "S", autoFixable: false, references: ["PCI-DSS 3.5", "OWASP A07:2021", "CWE-798"],
        }));
      }

      // PAY-3 / PAY-13 — tutar istemciden. Refund bağlamında over-refund (PAY-13),
      // diğer hallerde ödeme fiyat manipülasyonu (PAY-3).
      if (AMOUNT_FROM_CLIENT.test(ln) && (PAY_CODE.test(content) || fileHasCharge)) {
        if (fileHasRefund) {
          push(makeFinding({
            id: `PAY-13-refund-amount:${path}:${i + 1}`, title: "İade tutarı istemci girdisinden alınıyor (over-refund / iade sahtekârlığı)",
            severity: "P1", module: "PAY", check: "PAY-13", category: "Payment Refund Accounting", confidence: "medium",
            evidence: [{ type: "file", source: path, location: loc, excerpt: ln.trim().slice(0, 160) }],
            impact: "İade tutarı istemciden geldiği için saldırgan orijinal ödemeden fazlasını (ya da başkasının ödemesini) iade ettirebilir — doğrudan para kaybı.",
            recommendation: "İade tutarını ASLA istemciden alma. Sunucuda orijinal charge/intent'i bul; iadeyi o tutarla sınırla; çağıranın o ödemeye sahip olduğunu doğrula; kısmi iadelerde kalan bakiyeyi muhasebeleştir.",
            effort: "M", autoFixable: false, references: ["OWASP A04:2021", "CWE-840"],
          }));
        } else {
          push(makeFinding({
            id: `PAY-3-client-amount:${path}:${i + 1}`, title: "Ödeme tutarı istemci girdisinden alınıyor (fiyat manipülasyonu)",
            severity: "P0", module: "PAY", check: "PAY-3", category: "Payment Amount Tampering", confidence: "medium",
            evidence: [{ type: "file", source: path, location: loc, excerpt: ln.trim().slice(0, 160) }],
            impact: "Tutar istemciden geldiği için saldırgan isteği değiştirip 1000₺'lik ürüne 1₺ (hatta 0) ödeyebilir.",
            recommendation: "Tutarı ASLA istemciden alma. Sunucuda sepeti/ürünü DB'den yeniden fiyatla; para birimini de sunucuda sabitle ve doğrula.",
            effort: "M", autoFixable: false, references: ["OWASP A04:2021", "CWE-840"],
          }));
        }
      }

      // PAY-5 — kart verisi loglama/sunucuda işleme (PCI).
      if (CARD_LOG.test(ln)) {
        push(makeFinding({
          id: `PAY-5-card-data:${path}:${i + 1}`, title: "Kart verisi (PAN/CVV) loglanıyor veya sunucuda işleniyor",
          severity: "P1", module: "PAY", check: "PAY-5", category: "PCI / Card Data", confidence: "medium",
          evidence: [{ type: "file", source: path, location: loc, excerpt: maskSecrets(ln.trim().slice(0, 160)) }],
          impact: "Ham PAN/CVV log/sunucuya değerse PCI-DSS kapsamı patlar; CVV'yi saklamak kesinlikle yasaktır.",
          recommendation: "Kartı sunucuya hiç alma — sağlayıcının tokenizasyonu/hosted fields/Elements'ini kullan. CVV'yi asla sakla/logla; log'larda kart alanlarını redakte et.",
          effort: "M", autoFixable: false, references: ["PCI-DSS 3.2", "PCI-DSS 3.4", "PCI-DSS 10.2"],
        }));
      }
    }
  }

  // --- Proje düzeyi güvenilirlik (yokluk-temelli; ödeme entegrasyonu kesin varken) ---
  const anchor = data.files[0]?.path ?? "payment-integration";

  // PAY-7 — mutabakat (reconciliation) job'ı yok.
  if (!data.hasReconciliation) {
    push(makeFinding({
      id: "PAY-7-no-reconciliation", title: "Ödeme mutabakatı (reconciliation) tespit edilemedi",
      severity: "P1", module: "PAY", check: "PAY-7", category: "Payment Reliability", confidence: "low",
      evidence: [{ type: "config", source: anchor, excerpt: "ödeme entegrasyonu var; sağlayıcı ↔ DB mutabakat işi bulunamadı" }],
      impact: "Mutabakat olmadan sağlayıcıda çekilmiş ama DB'de kaydı olmayan (ya da tersi) ödemeler sessizce birikir — para/sipariş tutarsızlığı fark edilmez.",
      recommendation: "Periyodik (cron) bir mutabakat işi ekle: sağlayıcının charge/payout/balance kayıtlarını yerel sipariş/ödeme kayıtlarıyla karşılaştır; farkları alarma bağla.",
      effort: "L", autoFixable: false, references: ["PCI-DSS 10.6", "Ops: reconciliation"],
    }));
  }

  // PAY-11 — abonelik var ama başarısız yenileme/dunning işlenmiyor.
  if (data.usesSubscriptions && !data.hasDunning) {
    push(makeFinding({
      id: "PAY-11-no-dunning", title: "Abonelik var ama başarısız yenileme (dunning) işlenmiyor",
      severity: "P2", module: "PAY", check: "PAY-11", category: "Payment Reliability", confidence: "low",
      evidence: [{ type: "config", source: anchor, excerpt: "recurring/subscription kullanılıyor; invoice.payment_failed / past_due / dunning-retry işleme bulunamadı" }],
      impact: "Yenileme ödemesi başarısız olduğunda (kart doldu/limit) gelir sessizce kaybolur ya da müşteri ödemediği halde erişimi sürer.",
      recommendation: "invoice.payment_failed / payment_action_required / customer.subscription.deleted olaylarını işle; akıllı yeniden deneme (dunning) + grace period + erişim askıya alma kur.",
      effort: "M", autoFixable: false, references: ["Stripe Billing: dunning", "Ops: revenue recovery"],
    }));
  }

  // PAY-9 — kesinti/orphan ödeme koruması yok (para boşa düşer).
  if (!data.hasPendingState && !data.hasSweep) {
    push(makeFinding({
      id: "PAY-9-orphan-payment", title: "Kesinti/orphan ödeme koruması yok — çekilmiş ödeme boşa düşebilir",
      severity: "P1", module: "PAY", check: "PAY-9", category: "Payment Reliability", confidence: "low",
      evidence: [{ type: "config", source: anchor, excerpt: "ara 'pending/authorized' ödeme durumu persist edilmiyor ve bekleyen/stale ödeme süpürmesi yok" }],
      impact: "Ödeme sağlayıcıda başarılı olup uygulama o anda çökerse (ya da auth alınıp capture edilmezse) müşteri ödediği halde karşılığını almaz; auth'lar boşa expire olur.",
      recommendation: "Sağlayıcıyı çağırmadan ÖNCE yerel 'pending' ödeme kaydı oluştur (intent id ile); başarıda idempotent şekilde 'captured'a geçir; bekleyen/uncaptured kayıtları periyodik süpürüp capture/void et. Sipariş oluşturmayı payment intent id'ye idempotent bağla.",
      effort: "L", autoFixable: false, references: ["Ops: exactly-once fulfillment", "Stripe: async & recovery"],
    }));
  }

  return findings;
}

export const payModule: WardenModule = {
  id: "PAY",
  title: "Ödeme Güvenliği & Güvenilirliği",
  active: false,
  applicable(ctx: ScanContext) {
    return collectPayData(ctx.fs).usesPayments;
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const findings = analyzePay(collectPayData(ctx.fs));
    ctx.audit.info(`PAY: ${findings.length} bulgu.`);
    return { findings };
  },
};

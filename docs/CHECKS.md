# Warden — Kontrol Kataloğu

Tüm denetim kontrollerinin tek kaynağı. Her kontrol bir `Finding` üretebilir.
Sütunlar: **ID** · **Kontrol** · **Tip** (pasif/aktif) · **Tipik şiddet** · **Faz** · **Durum** · **Standart eşleştirme**.

Durum: ✅ uygulandı · 🚧 kısmen · ⏳ planlı.
Şiddet: P0 (blocker) · P1 (müşteri öncesi) · P2 (mimari borç) · P3 (iyileştirme).

> **Faz 0 (tamam):** Bu katalog + yetki kapısı + bulgu modeli + boş-ama-geçerli rapor üretici.
> Aşağıdaki kontroller fazlara dağıtılmıştır; uygulama ilgili fazda yapılır (iş emri §7 + genişletmeler).

---

## Modül A — Parity & Deployment Discovery (pasif) · Faz 1

| ID | Kontrol | Tip | Şiddet | Faz | Durum | Eşleştirme |
|----|---------|-----|:------:|:---:|:-----:|------------|
| A1 | Kod parity: prod git HEAD vs ana dal (production drift), commit gecikmesi, kirli çalışma ağacı | pasif | P0 | 1 | ✅ | — |
| A2 | Şema/DB parity (Prisma derin): **yıkıcı migration (DROP/TRUNCATE)=veri kaybı**, db push, shadow DB, migration eksikliği | pasif | P0 | 1 | ✅ | — |
| A3 | Çalışma zamanı tazeliği: konteyner güncel koddan mı, healthy mi, crash-loop (Docker) | pasif | P1 | 1 | 🚧 | canlı runtime gerekir |
| A4 | Storage/config parity: **generic volume parity engine** (producer/consumer/worker), `.env` ↔ `.env.example` | pasif | P1 | 1 | ✅ | — |
| A5 | Operasyonel sağlık: backup-ama-restore-yok, **TLS cert expiry** (X509); queue/DLQ/disk runtime'da | pasif | P1 | 1 | ✅ | — |
| A6 | Dış bağımlılık: yerel/geçici webhook URL (statik); OAuth scope & key geçerliliği canlı doğrulama | pasif | P2 | 1 | 🚧 | canlı doğrulama gerekir |

## Modül B — Statik Uygulama Güvenliği / SAST (pasif) · Faz 2

| ID | Kontrol | Tip | Şiddet | Faz | Durum | Eşleştirme |
|----|---------|-----|:------:|:---:|:-----:|------------|
| B1 | Secret taraması (kod + commit'lenmiş .env): AWS/private key/Slack/GitHub/Stripe/Google/GitLab/npm token, sabit secret, **entropi tabanlı** tespit, **git geçmişi** taraması | pasif | P0 | 2 | ✅ | gitleaks/trufflehog · OWASP A07 |
| B2 | Bağımlılık zafiyetleri: npm/pnpm audit (v6/v7 parser) + **OSV-Scanner** çok-ekosistem adapteri (`WARDEN_OSV=1`/import). pip-audit/govulncheck Faz 6 | pasif | P1 | 2 | ✅ | OWASP A06 · OSV/Snyk/Trivy |
| B3 | Zayıf kripto: MD5/SHA1, ECB, CryptoJS EvpKDF, token için `Math.random()`, **sabit/statik IV** (`createCipheriv`, `AES.new`) | pasif | P1 | 2 | ✅ | OWASP A02 · ASVS 6.2 · CWE-329 |
| B4 | Auth tasarımı: uzun JWT TTL, **JWT `alg:none`**, **zayıf/sözlük JWT secret'ı**. Refresh rotation/session fixation 🚧. *(JWT-in-localStorage → Modül FE / FE-1)* | pasif | P0 | 2 | ✅ | OWASP A07 · ASVS 3.x |
| B5 | Authz / multi-tenancy: IDOR adayı (heuristic, düşük güven). Tam RLS/tenant semantiği manuel | pasif | P1 | 2 | 🚧 | OWASP A01 · API1 (BOLA) · ASVS 4.x |
| B6 | Injection: ham SQL concat, command injection, eval, **SSTI, path traversal, SSRF, open redirect, XXE, NoSQL (`$where` + operatör), LDAP** | pasif | P0 | 2 | ✅ | OWASP A03/A10 · semgrep |
| B8-deser | **Güvensiz deserialization** (node-serialize/vm · pickle/yaml.load · PHP unserialize · .NET BinaryFormatter) | pasif | P0 | 2 | ✅ | OWASP A08 |
| B7 | Web sertleştirme: CORS wildcard. helmet/HSTS/rate-limit/CSRF varlığı 🚧 | pasif | P1 | 2 | 🚧 | OWASP A05 |
| B8 | Girdi doğrulama kapsamı: Zod/Joi/pydantic endpoint kapsamı | pasif | P2 | 2 | ⏳ | ASVS 5.x |
| B9 | Bilgi sızıntısı: yanıtta stack trace. debug flag/source map 🚧 | pasif | P2 | 2 | 🚧 | OWASP A05 |

> **Recall sınırı (dürüst not):** tarayıcı **satır bazlıdır**. NoSQL/LDAP filtresi ya da IV önce
> ayrı bir değişkende kurulup sonra çağrıya verilirse kaçırılır. Veri-akışı (taint) analizi
> gelene kadar bu bilinçli bir sınırdır.

## Modül C — Dinamik / DAST & Pentest (AKTİF — yetki kapılı) · Faz 4

> ⚠ Tümü `warden.authz.yml` + allow-list gerektirir. Rate-limited, non-destructive, audit-loglu.

| ID | Kontrol | Tip | Şiddet | Faz | Durum | Eşleştirme |
|----|---------|-----|:------:|:---:|:-----:|------------|
| C1 | Açıkta kalan dosya probe: `/.env`, `/.git/config`, `/backup.sql`, `/.tfstate`, swagger/actuator (içerik doğrulayıcılı) + **dizin listeleme / autoindex** (iki-sinyal doğrulayıcılı; listede `.env`/`.sql` görünürse P0) | aktif | P0 | 4 | ✅ | OWASP A05 · CWE-548 |
| C2 | Security header & TLS (canlı): HSTS/CSP/X-Frame/nosniff + TLS sürüm/cert (node:tls) | aktif | P1 | 4 | ✅ | Mozilla TLS · CIS |
| C3 | Korumasız admin paneli (GET, non-destructive). Default-cred DENEMESİ kasıtlı yapılmaz | aktif | P0 | 4 | ✅ | OWASP A01/A05 |
| C4 | Rate-limit eşik testi: düşük-hacim (5 GET) 429 alıyor mu | aktif | P1 | 4 | ✅ | OWASP API4 |
| C5 | Açık port/servis envanteri: hassas port listesi (Redis/Mongo/PostgreSQL…), yalnızca allow_port_scan ile | aktif | P2 | 4 | ✅ | CIS |
| C6 | Cookie güvenliği (canlı): Secure/HttpOnly/SameSite | aktif | P1 | 4 | ✅ | OWASP A05 · ASVS 3.4 |

## Modül D — Uyum & Operasyonel Olgunluk (pasif) · Faz 3

| ID | Kontrol | Tip | Şiddet | Faz | Durum | Eşleştirme |
|----|---------|-----|:------:|:---:|:-----:|------------|
| D1 | Backup & DR: yedek + restore drill (A5 sinyali); retention/off-site manuel | pasif | P2 | 3 | ✅ | ISO 27001 A.12 |
| D2 | Gözlemlenebilirlik: hata izleme (Sentry/Datadog/OTel) bağımlılık tespiti | pasif | P2 | 3 | ✅ | OWASP A09 · CWE-778 |
| D3 | Secret yönetimi: vault/KMS/secret-manager bağımlılığı yoksa düz `.env` uyarısı | pasif | P2 | 3 | ✅ | ISO 27001 A.10 |
| D4 | Veri koruma (GDPR/KVKK): soft-delete (deletedAt) tespiti; export/retention manuel | pasif | P2 | 3 | ✅ | KVKK/GDPR |
| D5 | CI/CD hijyeni: pipeline + test/lint kapısı tespiti (GitHub/GitLab/Circle/Azure/Jenkins) + **artifact imzalama (cosign/sigstore) · SLSA provenance · SBOM yokluğu** | pasif | P2 | 3 | ✅ | SLSA v1.0 · OWASP A08 |
| D6 | Rollback yeteneği: migration geri-alınabilirliği | pasif | P2 | 3 | ⏳ | — |
| **D7** | **PCI-DSS 4.0:** CVV saklama (P0 yasak), PAN saklama/maskeleme (P1) + **PCI checklist** (TLS/MFA/logging) | pasif | P0 | 3 | ✅ | PCI-DSS 4.0 |
| **D8** | **Privacy:** soft-delete + cookie-consent tespiti + **Privacy checklist** (silme/export/consent/retention) | pasif | P1 | 3 | ✅ | KVKK/GDPR |

## OWASP Top 10 (2021) — uyum checklist'i · v0.10

> **Değişiklik (v0.10): "Modül E" kaldırıldı.** OWASP Top 10 bir **taksonomidir**, bir tarama
> boyutu değil. `MODULES` ve `DIMENSIONS` içinde `E` tanımlıydı ama hiçbir modül `module: "E"`
> emit etmiyordu → skor tablosunda **kalıcı, yanıltıcı bir `n/d` satırı** duruyordu. Oysa OWASP
> kapsamı fiilen vardı: repoda 96 adet `OWASP A0x:2021` referansı.
>
> Artık OWASP kapsamı, **çalışan modüllerin bulgularından** hibrit olarak türetilen bir uyum
> checklist'idir (`risk/owasp.ts`):
> **L1** bulgunun `references` alanındaki `OWASP A0x:2021` kodu · **L2** `check`/`module`/`id`
> önekinden türetme. L2 zorunludur: `cloud`, `k8s`, `parity`, `compliance` ve SARIF/OSV
> içe-aktarımı bulguları OWASP referansı taşımaz, saf referans-ayrıştırma bunlara kördür.
>
> Çıktı: `compliance-report.md` · `report.md` → "Uyum Özeti" · `findings.json.checklists`.
>
> **Durum yalnızca ✖ Failed veya – Unknown olabilir.** Warden statik analizle "bu kategoriden
> geçtiniz" iddia etmez (dürüst raporlama, iş emri §8).

| OWASP 2021 | Besleyen Warden kontrolleri | Durum |
|---|---|:--:|
| A01 Broken Access Control | B5 (IDOR) · ACC-1..4 · C3 · WEB-1 · UPLOAD-2 · `B6-path-traversal` · `B7-open-redirect` · CLOUD public-storage / IAM-wildcard / RDS-public | ✅ |
| A02 Cryptographic Failures | B3 (MD5/SHA1/ECB/CryptoJS/`Math.random`/**sabit IV**) · `B3-go-insecure-tls` · PRIV-3 · `A5-cert-expiry` · AI-3 | ✅ |
| A03 Injection | B6 (SQL · komut · eval · SSTI · **NoSQL** · **LDAP**) · FE-3 (DOM-XSS sink'leri) · EMAIL-1/2 | ✅ |
| A04 Insecure Design | ACC-2 · tüm PAY · FLOW-1..3 · UPLOAD-1/3 | 🚧 |
| A05 Security Misconfiguration | B7 · B9 · FE-2/4/6/7 · C1 (**dizin listeleme** dahil) · C2/C5/C6 · WEB-2/3 · API-4 · `B6-xxe` · tüm K8S · CLOUD ağ/SSL | ✅ |
| A06 Vulnerable & Outdated Components | B2 (npm/pnpm audit · OSV) · CVE taşıyan SARIF/OSV içe-aktarımları | ✅ |
| A07 Identification & Auth Failures | B1 (secret) · B4 (JWT TTL · `alg:none` · **zayıf secret**) · FE-1 · AUTH-1..6 · D3 · `K8S-plain-secret` | ✅ |
| A08 Software & Data Integrity | `B8-*` güvensiz deserialization · D5 (**imzasız artifact / SLSA provenance / SBOM**) | ✅ |
| A09 Logging & Monitoring Failures | D2 (hata izleme yok) · PRIV-1/2 (PII log/URL) · PRIV-5 (audit trail yok) | 🚧 |
| A10 SSRF | `B6-ssrf-node` · `B6-ssrf-py` | ✅ |
| ASVS | Bulgu referanslarından ✖/– checklist (`risk/asvs.ts`) — değişmedi | ✅ |

> **A04 ve A09 neden 🚧?** İkisi de yalnızca yokluk-temelli heuristiklerle besleniyor:
> tehdit-modeli tespiti yok, alarm/SIEM/saklama doğrulaması yok. ✅ demek yanıltıcı olurdu.
>
> **⚠ Göç notu (v0.10):** `check: "E3" | "E8" | "E10"` kodları `B6`/`B8`'e normalize edildi.
> `check` hem fingerprint bileşeni hem waiver seçicisi olduğu için: (a) bu 7 kuralın
> fingerprint'i **bir kez** değişir (delta raporunda tek seferlik "fixed + new"), (b)
> `.warden-ignore.yml` içinde bu kodları kullanan waiver'ları güncelleyin — Warden çalıştırmada
> bunun için açık uyarı verir.

## Modül CLOUD — Cloud Security (pasif/IaC; canlı kısımlar yetki kapılı) · Faz 6+

| ID | Sağlayıcı | Kontroller | Faz | Durum | Eşleştirme |
|----|-----------|-----------|:---:|:-----:|------------|
| CLOUD-AWS | AWS | Public S3 · IAM wildcard · Open Security Group (0.0.0.0/0) · RDS Public (Terraform) | + | ✅ | CIS AWS Benchmark |
| CLOUD-AZ | Azure | Storage Public Access (Terraform) | + | ✅ | CIS Azure |
| CLOUD-CF | Cloudflare | SSL mode flexible | + | ✅ | — |
| CLOUD-GCP | GCP | public bucket (allUsers) · Cloud SQL public · firewall 0.0.0.0/0 (Terraform) | + | ✅ | CIS GCP |

## Modül K8S — Kubernetes (pasif manifest analizi) · Faz 6+

| ID | Kontrol | Faz | Durum | Eşleştirme |
|----|---------|:---:|:-----:|------------|
| K8S-1 | Privileged containers | + | ✅ | CIS K8s 5.2 |
| K8S-2 | Root containers (runAsNonRoot yok) | + | ✅ | CIS K8s 5.2 |
| K8S-3 | imagePullPolicy / latest tag | + | ✅ | — |
| K8S-4 | Exposed secrets (env/manifest) | + | ✅ | CIS K8s 5.4 |
| K8S-5 | Ingress misconfig (TLS yok) | + | ✅ | — |

## Modül API — API Güvenliği (OWASP API Top 10, pasif) · Faz 6+

ACCESS (BOLA/authz) ve B (injection) dışında kalan API-özgü riskler. Yalnızca bir HTTP/API yüzeyi
tespit edilirse koşar; yokluk-temelli bayraklar yorumsuz kodda aranır.

| ID | Kontrol | Faz | Durum | Eşleştirme |
|----|---------|:---:|:-----:|------------|
| API-1 | Aşırı veri ifşası: SELECT * / tüm kolonlar dönüyor | + | ✅ | OWASP API3 · CWE-213 |
| API-2 | API geneli hız sınırı (rate limit) yok | + | ✅ | OWASP API4 · CWE-770 |
| API-3 | Sınırsız sorgu: findMany/findAll limit/pagination olmadan | + | ✅ | OWASP API4 · CWE-770 |
| API-4 | Ayrıntılı hata/stack trace istemciye dönüyor | + | ✅ | OWASP API8 · CWE-209 |
| API-6 | GraphQL derinlik/karmaşıklık limiti yok | + | ✅ | OWASP API4 · CWE-770 |

> BOLA (API1) → ACCESS/ACC-1 · Broken Authentication (API2) → AUTH · BFLA (API5) → ACCESS/ACC-4.
> API yüzeyi yoksa modül hiç bulgu üretmez.

## Modül PRIV — Veri Gizliliği & Denetim İzi (pasif) · Faz 6+

CRM/ERP hassas kişisel veri (PII) yoğun — KVKK/GDPR uyumu. Yalnızca PII alanları tespit edilirse
koşar; yokluk-temelli bayraklar yorumsuz kodda aranır.

| ID | Kontrol | Faz | Durum | Eşleştirme |
|----|---------|:---:|:-----:|------------|
| PRIV-1 | PII loglanıyor (email/telefon/TCKN/IBAN log satırında) | + | ✅ | KVKK m.12 · GDPR Art.5 · CWE-532 |
| PRIV-2 | PII URL/query string'inde (access-log + referrer sızıntısı) | + | ✅ | GDPR Art.5 · CWE-598 |
| PRIV-3 | Yüksek-hassas alan at-rest şifreleme olmadan | + | ✅ | KVKK m.12 · GDPR Art.32 · CWE-311 |
| PRIV-4 | Silme/anonimleştirme (KVKK/GDPR unutulma hakkı) yok | + | ✅ | KVKK m.7 · GDPR Art.17 |
| PRIV-5 | Hassas veri erişim/değişiklik denetim izi (audit trail) yok | + | ✅ | GDPR Art.30 · ISO 27001 A.12.4 · OWASP A09 |

> PII yoksa PRIV hiç bulgu üretmez.

## Modül WEB — CSRF, Clickjacking & Güvenlik Başlıkları (pasif) · Faz 6+

Sunucu-taraflı web sertleştirme; Modül B'nin (CORS/XSS/CSP) ve C/DAST'ın (canlı header) statik
tamamlayıcısı — özellikle **CSRF** başka hiçbir modülde yok. Yalnızca bir web yüzeyi (Express/
Fastify/Koa/route decorator) tespit edilirse koşar; yokluk-temelli bayraklar yorumsuz kodda aranır.

| ID | Kontrol | Faz | Durum | Eşleştirme |
|----|---------|:---:|:-----:|------------|
| WEB-1 | CSRF koruması yok (çerez-tabanlı oturum + state-değiştiren route, token/SameSite=strict yok) | + | ✅ | OWASP A01 · CWE-352 · ASVS 4.2 |
| WEB-2 | Güvenlik başlıkları / clickjacking koruması yok (helmet/X-Frame-Options/HSTS/CSP/nosniff) | + | ✅ | OWASP A05 · CWE-1021 · CWE-693 |
| WEB-3 | Yansıtılan CORS origin + credentials (origin: req.origin → herkese kimlikli erişim) | + | ✅ | OWASP A05 · CWE-942 |

> Web yüzeyi yoksa WEB hiç bulgu üretmez. CSRF/başlık bayrakları düşük güven (heuristik) — token'lı
> (çerezsiz) API'lerde CSRF alakalı değildir; `.warden-ignore.yml` ile bastırılabilir.

## Modül FLOW — İş-Akışı & Veri Bütünlüğü (pasif) · Faz 6+

CRM/ERP güvenilirliği: para/stok/durum tutan iş akışlarında sessiz veri bozulması — PAY-9'un
(orphan ödeme) ödemeye özel olmayan genelleştirmesi. Handler gövdeleri süslü-parantez eşlemeyle
çıkarılır; her kontrol handler bazında değerlendirilir. Yalnızca web yüzeyi varsa koşar.

| ID | Kontrol | Faz | Durum | Eşleştirme |
|----|---------|:---:|:-----:|------------|
| FLOW-1 | Transaction'sız çok-adımlı yazma (yarıda kesilirse yarım/tutarsız durum) | + | ✅ | CWE-662 · CWE-460 · ASVS 11.1 |
| FLOW-2 | Atomik olmayan oku-değiştir-yaz sayaç/bakiye/stok (lost update / race) | + | ✅ | CWE-362 · CWE-567 · OWASP A04 |
| FLOW-3 | İdempotent olmayan sipariş/transfer/rezervasyon oluşturma (çift-gönderim) | + | ✅ | CWE-799 · ASVS 11.1 |

> Web yüzeyi yoksa FLOW hiç bulgu üretmez. Bulgular düşük güven (heuristik) — bilinçli tekil yazma
> ya da kuyruğa dayalı akışlarda `.warden-ignore.yml` ile bastırılabilir.

## Modül EMAIL — E-posta Güvenliği (pasif) · Faz 6+

E-posta güvenliğinin **kod-seviyesinde statik saptanabilen** dilimi. Yalnızca bir mailer/SMTP
yüzeyi (nodemailer, SendGrid, SES, Mailgun, Postmark, Resend, smtplib, PHPMailer…) varsa koşar.

| ID | Kontrol | Faz | Durum | Eşleştirme |
|----|---------|:---:|:-----:|------------|
| EMAIL-1 | E-posta header injection (kullanıcı girdisi from/replyTo/sender/cc/bcc/headers'a) | + | ✅ | CWE-93 · CWE-159 · OWASP A03 |
| EMAIL-2 | HTML e-posta gövdesine kaçışsız kullanıcı girdisi (içerik enjeksiyonu / phishing) | + | ✅ | CWE-79 · CWE-80 · OWASP A03 |
| EMAIL-3 | TLS'siz / doğrulamasız SMTP taşıması (secure:false / port 25 / ignoreTLS / rejectUnauthorized:false) | + | ✅ | CWE-319 · OWASP A02 |

> **SPF/DKIM/DMARC** kaynak koddan görülemez — canlı domain karşısında DNS sorgusuyla doğrulanır;
> bu, Modül C/DAST'ın (yetki kapılı, canlı hedef) yeridir, statik analizin değil.
> Mailer yoksa EMAIL hiç bulgu üretmez.

## Modül UPLOAD — Dosya Yükleme Güvenliği (pasif) · Faz 6+

Neredeyse her SaaS/CRM/ERP dosya yükler; klasik yüksek-etkili açık sınıfı. Yalnızca bir yükleme
yüzeyi (multer/formidable/busboy/express-fileupload/@fastify/multipart…) varsa koşar.

| ID | Kontrol | Faz | Durum | Eşleştirme |
|----|---------|:---:|:-----:|------------|
| UPLOAD-1 | Kısıtsız dosya tipi (fileFilter / uzantı-MIME whitelist yok → webshell) | + | ✅ | OWASP A04 · CWE-434 · ASVS 12.1 |
| UPLOAD-2 | Kullanıcı dosya adıyla path traversal (originalname yola basename'siz giriyor) | + | ✅ | OWASP A01 · CWE-22 · CWE-23 |
| UPLOAD-3 | Yükleme boyut limiti yok (DoS / disk doldurma) | + | ✅ | OWASP A04 · CWE-400 · CWE-770 |
| UPLOAD-4 | Yüklenenler web-root'ta / çalıştırılabilir servis altında saklanıyor | + | ✅ | OWASP A04 · CWE-434 · CWE-552 |

> Yükleme yüzeyi yoksa UPLOAD hiç bulgu üretmez. Absence bayrakları (UPLOAD-1/3) düşük güven —
> whitelist/limit farklı bir katmanda (reverse-proxy, gateway) uygulanıyorsa `.warden-ignore.yml`.

---

## Modül FE — Frontend Security (React/Next/Vue/Svelte/Astro, pasif) · Faz 2

Tarayıcıda çalışan kodun kendi saldırı yüzeyi: DOM-XSS sink'leri, token saklama, CSP zayıflığı,
cross-origin mesajlaşma ve tedarik zinciri (SRI). Yalnızca bir **frontend yüzeyi** tespit edilirse
koşar (`.jsx/.tsx/.vue/.svelte/.astro` dosyası **veya** `package.json`'da react/vue/svelte/astro/
next/nuxt/angular/solid/preact/remix/gatsby bağımlılığı). Yüzey yoksa FE boyutu `n/d` kalır;
**yüzey varsa ve bulgu yoksa 10/10 puanlanır.**

`.html/.htm/.njk/.ejs/.hbs` şablonları da taranır — SAST'ın `CODE_FILE` deseni bunları
kapsamaz, FE modülü `scanSource`'a kendi `include`'unu geçer. Ayrıca `maxDepth: 6` kullanır
(varsayılan 4, monorepo'da `apps/web/src/components/ui/X.tsx` = 5 dizin).

CSP · tabnabbing · SRI · message-origin kontrolleri **tek satıra sığmadığı için** satır-bazlı
kural yerine **pencere analiziyle** yapılır (`modules/fe/index.ts`).

| ID | Kontrol | Faz | Durum | Eşleştirme |
|----|---------|:---:|:-----:|------------|
| FE-1 | `localStorage`/`sessionStorage`'da JWT/token (`setItem` · `[...]=` · `.authToken=`) | 2 | ✅ | OWASP A07:2021 · ASVS 3.4 |
| FE-2 | Zayıf CSP: `unsafe-inline`/`unsafe-eval` — **çok satırlı helmet/Next.js yazımı dahil** | 2 | ✅ | OWASP A05:2021 · CWE-1021 |
| FE-3 | DOM-XSS sink'leri: `dangerouslySetInnerHTML` · Vue `v-html` · Svelte `{@html}` · Astro `set:html` · `innerHTML`/`outerHTML`/`document.write`/`insertAdjacentHTML` · `javascript:` URL · doğrulanmamış `href={…}` binding | 2 | ✅ | OWASP A03:2021 · CWE-79 · ASVS 5.3 |
| FE-4 | Üretimde source map açık (`vite/webpack/next/nuxt/astro.config.[cm]?[jt]s`) | 2 | ✅ | OWASP A05:2021 · CWE-540 |
| FE-5 | Cross-origin mesajlaşma: `postMessage(x, "*")` · `message` dinleyicisinde `origin` doğrulaması yok | + | ✅ | OWASP A05:2021 · CWE-942 · CWE-346 |
| FE-6 | `target="_blank"` + `rel="noopener"` yok (reverse tabnabbing) | + | ✅ | OWASP A05:2021 · CWE-1022 |
| FE-7 | Harici script/stylesheet SRI (`integrity`) yok — CDN ele geçirme / Magecart | + | ✅ | OWASP A08:2021 · CWE-353 |

> **Heuristik / düşük güvenli kontroller** (`.warden-ignore.yml` ile bastırılabilir):
> `FE-unsafe-url-binding` (P2/low — `href={link.url}` gibi meşru kullanımlar FP olabilir) ·
> `FE-message-no-origin` (P1/low — yokluk temelli) · `FE-sri-missing` (P2/medium — GTM/analytics
> loader'ları tasarım gereği SRI kullanamaz) · `FE-tabnabbing` (**P3** — modern tarayıcılar
> `noopener`'ı örtük uygular; yalnızca eski tarayıcı desteği için gerekli).
>
> **⚠ Göç notu (v0.10):** Bu kontroller daha önce Modül B'nin (`sast/rules.ts`) içindeydi ve FE
> boyutu yalnızca **bulgu varken** puanlanıyordu — temiz bir frontend asla 10/10 alamıyor, daima
> `n/d` görünüyordu. Ayrıca `FE-2` (çok satırlı CSP) ve `FE-vue-vhtml`'in `.html` kısmı pratikte
> **ölü kuraldı**. `FE-1`'in `check` kodu `B4` → `FE-1` düzeltildiği için o kuralın
> **fingerprint'i bir kez değişir** (delta raporunda tek seferlik "fixed + new").

## Modül AI — AI / LLM Security (pasif) · Faz 6+

| ID | Kontrol | Faz | Durum | Eşleştirme |
|----|---------|:---:|:-----:|------------|
| AI-1 | Prompt Injection yüzeyi (kullanıcı girdisi prompt'a birleşiyor) | + | ✅ | OWASP LLM01 |
| AI-2 | RAG/sistem-prompt sızıntısı (log/yanıt) | + | ✅ | OWASP LLM06 |
| AI-3 | Gömülü LLM API key (OpenAI/Anthropic/...) | + | ✅ | OWASP LLM02 |

> CLOUD/K8S/AI modülleri yalnızca ilgili dosyalar (IaC `.tf` · k8s manifest · AI SDK) bulununca koşar (gürültü önleme).

## Modül PAY — Ödeme Güvenliği & Güvenilirliği (pasif) · Faz 6+

Yalnızca bir ödeme entegrasyonu (Stripe, PayPal, Braintree, Adyen, Razorpay, Mollie, iyzico,
craftgate, PayU…) tespit edilirse koşar. Para-akışına özgü hataları arar; yokluk-temelli
güvenilirlik kontrolleri (PAY-7/8/9/10) heuristiktir → düşük/orta güven, `.warden-ignore.yml` ile
bastırılabilir.

| ID | Kontrol | Faz | Durum | Eşleştirme |
|----|---------|:---:|:-----:|------------|
| PAY-1 | Ödeme secret anahtarı sızıntısı (sk_live_/whsec_ … client bundle'da → P0 felaket) | + | ✅ | PCI-DSS 3.5 · OWASP A07 · CWE-798 |
| PAY-2 | Webhook imza doğrulaması yok (sahte "ödeme başarılı") | + | ✅ | OWASP A08 · CWE-345 |
| PAY-3 | Tutar istemciden alınıyor (fiyat manipülasyonu) | + | ✅ | OWASP A04 · CWE-840 |
| PAY-4 | Charge oluşturma idempotency-key'siz (retry'da çift çekim) | + | ✅ | Stripe idempotency |
| PAY-5 | Kart verisi (PAN/CVV) loglanıyor/sunucuda işleniyor | + | ✅ | PCI-DSS 3.2/3.4/10.2 |
| PAY-7 | Mutabakat (reconciliation) job'ı yok (sağlayıcı ↔ DB tutarsızlığı) | + | ✅ | PCI-DSS 10.6 |
| PAY-8 | Webhook olay tekilleştirme (dedup) yok (çift teslim/iade) | + | ✅ | CWE-696 |
| PAY-9 | Kesinti/orphan ödeme koruması yok (çekilmiş ama karşılığı verilmemiş — para boşa) | + | ✅ | exactly-once fulfillment |
| PAY-10 | Başarısız/asenkron ödeme olayı işlenmiyor (para limboda) | + | ✅ | Stripe event handling |
| PAY-11 | Abonelik var ama dunning (başarısız yenileme) yok → gelir sızıntısı/bedava erişim | + | ✅ | Stripe Billing dunning |
| PAY-12 | 3DS/SCA desteklemeyen legacy Charges API (AB kartı red / PSD2 ihlali) | + | ✅ | PSD2 SCA |
| PAY-13 | İade tutarı istemciden (over-refund / iade sahtekârlığı) | + | ✅ | OWASP A04 · CWE-840 |

> Ödeme entegrasyonu yoksa PAY hiç bulgu üretmez ve boyut "n/d" kalır.

## Modül ACCESS — Erişim Kontrolü & Kiracı İzolasyonu (pasif) · Faz 6+

OWASP #1 (Broken Access Control) — SaaS/CRM/ERP'nin en pahalı ihlal noktası. Yalnızca bir web/API +
ORM yüzeyi tespit edilirse koşar. İş-mantığı yetkilendirmesi statik olarak zor olduğu için
heuristik → düşük/orta güvenle işaretlenir, `.warden-ignore.yml` ile bastırılabilir.

| ID | Kontrol | Faz | Durum | Eşleştirme |
|----|---------|:---:|:-----:|------------|
| ACC-1 | Kiracı izolasyonu: nesne istemci id'siyle çekiliyor, tenant/org filtresi yok (cross-tenant sızıntı) | + | ✅ | OWASP A01 · API1 BOLA · CWE-639 |
| ACC-2 | State-değiştiren endpoint auth middleware'i olmadan (proje geneli auth kullanıyorken) | + | ✅ | OWASP A01 · API5 |
| ACC-3 | Mass assignment / over-posting (req.body → model; is_admin escalation) | + | ✅ | OWASP A04 · API6 · CWE-915 |
| ACC-4 | Ayrıcalıklı/admin aksiyonu rol/izin kontrolü olmadan (yetki yükseltme) | + | ✅ | OWASP A01 · CWE-269 |

> Web/API yüzeyi yoksa ACCESS hiç bulgu üretmez. Multi-stack: Express/Fastify/Nest · Django · Rails · Laravel · Prisma/Sequelize/TypeORM/Mongoose.

## Modül AUTH — Kimlik & Oturum Sertleştirme (pasif) · Faz 6+

Hesap devri (account takeover) yüzeyi. Yalnızca bir kimlik/oturum yüzeyi (login/parola/jwt/session)
tespit edilirse koşar. Yokluk-temelli kontroller (AUTH-1/5/6) **yorumsuz kodda** aranır (yorumdaki
söz bastırmasın) ve düşük güvenle işaretlenir.

| ID | Kontrol | Faz | Durum | Eşleştirme |
|----|---------|:---:|:-----:|------------|
| AUTH-1 | MFA/2FA yok (login var, ikinci faktör yok) | + | ✅ | OWASP A07 · ASVS 2.8 |
| AUTH-2 | Tahmin edilebilir reset/doğrulama token'ı (Math.random/Date.now) | + | ✅ | CWE-330 · CWE-640 |
| AUTH-3 | Güvensiz oturum çerezi (httpOnly/secure/sameSite eksik/false) | + | ✅ | OWASP A05 · CWE-1004 |
| AUTH-4 | JWT süresiz (expiry yok) → çalınan token sonsuz geçerli | + | ✅ | CWE-613 |
| AUTH-5 | Login'de brute-force koruması yok (rate-limit/lockout) | + | ✅ | OWASP A07 · CWE-307 |
| AUTH-6 | Zayıf parola politikası (hash var, güç/pwned kontrolü yok) | + | ✅ | ASVS 2.1 · NIST 800-63B |

> Kimlik yüzeyi yoksa AUTH hiç bulgu üretmez.

---

## Çapraz Kesen Yetenekler (roadmap)

| Yetenek | Açıklama | Faz | Durum |
|---------|----------|:---:|:-----:|
| Risk skorlama: **CVSS v4 + Exploitability** | Her bulguya CVSS v4 taban skoru + exploitability (risk/score.ts eşleme tablosu) | 5 | ✅ |
| Remediation playbook zenginleştirme | risk + standart + etkilenen konumlar + adımlar + test/kabul + delta geri-besleme | 5 | ✅ |
| **SARIF export** | `findings.sarif` (SARIF 2.1.0, GitHub Code Scanning / Azure DevOps) | 1 | ✅ |
| Detection plugin sistemi | `StackDetector` arayüzü: node-prisma/drizzle/django/laravel/aspnet/go/docker/cloudflare | 1 | ✅ |
| Evidence Engine | ortak `{type, source, location, excerpt}` kanıt formatı | 1 | ✅ |
| Cloudflare detect (stub) | wrangler/cloudflare.toml/workers/pages/tunnel tespiti (kontroller sonraki) | 1 | ✅ |
| **İkinci stack: Django** | A2 Django yıkıcı migration + Python/Django SAST kuralları + D (Python deps) | 6 | ✅ |
| **`warden init` kurulumu** | `.claude/skills/warden/` (SKILL.md + README) + yetki şablonu | 6 | ✅ |
| Adaptör: **Laravel** | A2 Laravel yıkıcı migration + PHP/Laravel SAST (md5, exec/shell_exec, DB::raw, withoutGlobalScopes, $guarded=[], dd/dump) + D composer deps | + | ✅ |
| Adaptör: **.NET/ASP.NET** | A2 EF Core yıkıcı migration + C# SAST (MD5/SHA1, FromSqlRaw, Process.Start, UseDeveloperExceptionPage) + D .csproj deps | + | ✅ |
| Adaptör: **Go** | A2 golang-migrate yıkıcı up.sql + Go SAST (crypto/md5-sha1, Sprintf/concat SQL, exec.Command, InsecureSkipVerify) + D go.mod deps | + | ✅ |
| **GitHub Action** | composite `action.yml` + workflow; `--fail-on` CI gate; SARIF upload (Code Scanning) | + | ✅ |
| **Run-to-run delta (öncesi/sonrası)** | fingerprint tabanlı fixed/introduced/persisting + skor before→after + `history.jsonl` trend | 2 | ✅ |
| Continuous Monitoring Mode | `warden monitor --interval` periyodik tarama + delta (cron/Action ile de) | + | ✅ |
| **CIS Benchmark** eşleştirmesi | bulgulardan türetilen checklist (K8s/AWS/Azure/GCP/Docker) ✖/– | + | ✅ |
| **ISO 27001:2022** eşleştirmesi | bulgulardan türetilen Annex A checklist (A.5.15/8.8/8.9/8.13/8.15/8.24/8.25/8.28) ✖/– | + | ✅ |
| **Dış araç orkestrasyonu (SARIF/OSV içe-aktarım)** | `warden-imports/*.sarif` (OpenGrep/Semgrep/Trivy/Gitleaks/Checkov/Nuclei) + `*.osv.json` → Finding normalizasyonu; `WARDEN_OSV=1` canlı osv-scanner. Bulgular fingerprint/delta/skor/playbook/waiver/SARIF-export'a girer | 2 | ✅ |
| **KEV + EPSS önceliklendirme** | CVE taşıyan bulgulara CISA KEV (bilinen-sömürülen) + EPSS (30-gün olasılık); **çevrimdışı** `warden-data/kev.json` / `epss.json` anlık-görüntüsünden (ağsız) | 5 | ✅ |
| **Reachability (import-seviyesi)** | Zafiyetli bağımlılık kaynak import grafında mı; değilse (olası transitif) öncelik düşürülür (KEV hariç). Tam çağrı-grafı değil | 6 | ✅ |
| **Native araç runner'ları** | `WARDEN_TOOLS=all\|opengrep,semgrep,trivy,gitleaks,checkov` kuruluysa doğrudan çalıştırır → SARIF normalize; **nuclei** yetki-kapılı (DAST, non-destructive etiketler). Kurulu değilse graceful atlar. OSV native runner ✅ | 2/4 | ✅ |
| **İçe-aktarım modül ataması** | SARIF bulguları araç adından modüle atanır (checkov→CLOUD, kubescape→K8S, nuclei/zap→C, semgrep/gitleaks/trivy→B); scoreboard boyutları buna göre | 2 | ✅ |

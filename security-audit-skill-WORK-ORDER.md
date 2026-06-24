# İŞ EMRİ — "Warden" Production-Readiness & Security Audit Skill

> **Bu dosya bir iş emridir.** Başka bir projede, başka bir Claude Code ajanına verilecek.
> Ajan bu dökümanı okuyup **yeni bir GitHub reposu** olarak `warden` adlı taşınabilir
> bir denetim skill'i inşa edecek. "Warden" çalışma adıdır; ajan değiştirebilir.
>
> **Kaynak motivasyon:** Bir SaaS projesinde elle yaptığımız "discovery-first production
> stabilization" oturumunu (kod/şema/konteyner/altyapı/operasyonel parity doğrulaması +
> güvenlik gözlemleri) tekrarlanabilir, herhangi bir projeye eklenebilir bir araca dönüştürmek.

---

## 0. Tek cümlelik tanım

**Warden**, bir projeye eklenen; o projenin tüm kaynak kodunu, konfigürasyonunu, bağımlılıklarını
ve (yetki verilirse) çalışan production ortamını analiz edip **eksik/hatalı/riskli** her şeyi
şiddet sırasına göre listeleyen, kanıtlı bulgular üreten ve sonunda **doğrudan uygulanabilir bir
Claude Code düzenleme/remediation playbook'u** veren bir **Claude Code Skill + destek script seti**.

---

## 1. Ne YAPAR / Ne YAPMAZ

**YAPAR:**
- Projeyi statik analiz eder (kod, şema, bağımlılık, secret, config, IaC).
- Production ↔ local **parity**'sini kanıtla doğrular (bu oturumun 6 katmanı).
- Pasif güvenlik denetimi (security header, TLS, açıkta kalan dosya, auth tasarımı).
- **Yetki verilirse** aktif/sızma testleri (auth-bypass denemeleri, rate-limit, exposed endpoint probe).
- Şiddet sıralı, kanıtlı bulgu raporu (`report.md` + `findings.json`).
- Her P0/P1 için **hazır Claude Code remediation prompt'ları**.

**YAPMAZ (sınır çizgisi):**
- Hedef sisteme **kalıcı değişiklik** yapmaz (read-only; remediation'ı kullanıcı/ayrı ajan uygular).
- Yetkisiz hedefe aktif test **çalıştırmaz** (bkz. §2 Yetki Kapısı).
- DoS, mass-targeting, exploit silahlandırma, tespit-atlatma üretmez.
- Üretim verisini dışarı sızdırmaz; secret'ları rapora **maskeli** yazar.

---

## 2. ⭐ GÜVENLİK & YETKİLENDİRME İLKELERİ (en kritik bölüm)

Bu araç **savunma amaçlı bir öz-denetim** aracıdır. Aktif/saldırgan yetenekler **çift kullanımlıdır**;
bu yüzden katı kurallar:

1. **Varsayılan tamamen PASİF/READ-ONLY.** Hiçbir aktif test varsayılan çalışmaz.
2. **Yetki Kapısı (Authorization Gate):** Aktif testler yalnızca proje kökünde bir
   `warden.authz.yml` dosyası varsa VE içinde şu alanlar doluysa çalışır:
   - `owner_attestation: true` ("bu varlıklar bana ait / yetkiliyim" beyanı)
   - `authorized_targets:` (yalnızca bu host/domain/IP'lere aktif test yapılır; allow-list)
   - `authorized_by:` ve `date:` (denetim izi)
   Allow-list dışı hiçbir hedefe aktif istek gönderilmez. Dosya yoksa skill **yalnızca pasif** koşar.
3. **Intrusive olmayan eşik:** Aktif testler bile rate-limited, non-destructive ve düşük-hacimdir
   (DoS yok, brute-force yok — yalnızca "default cred var mı / endpoint açıkta mı / header doğru mu").
4. **Secret maskeleme:** Bulunan token/parola/URL rapora `***` ile yazılır; tam değer asla loglanmaz.
5. **Audit log:** Skill kendi çalıştırdığı her aktif komutu `warden-run.log`'a yazar (şeffaflık).
6. **Üretimde mutasyon yok:** Komutlar `--dry-run`/diff/inspect seviyesinde kalır; deploy/migrate/restart YOK.

> Bu ilkeler README'nin en üstünde ve skill açılış çıktısında da tekrarlanmalı.

---

## 3. Form faktörü & dağıtım

- **Claude Code Skill** olarak paketlenir (SKILL.md + `scripts/`). Bir projeye iki yolla eklenir:
  - (a) repo'yu `.claude/skills/warden/` altına kopyalayarak, veya
  - (b) `npx warden init` benzeri bir kurulum komutuyla skill dosyalarını projeye yerleştirerek.
- **Stack-agnostik çekirdek + adaptörler.** Çekirdek mantık dilden bağımsız; her stack için bir adaptör:
  - **first-class:** Node/TS + Prisma + Docker (Turborepo/pnpm, Express/Next, docker-compose, Cloudflare).
  - **destekli:** Genel Node/JS (TypeORM/Drizzle/Knex, Fastify/Nest), Python (Django/FastAPI/Alembic), Go, PHP/Laravel.
  - **infra-only:** dil-bağımsız Docker/k8s/systemd/TLS/DNS/backup/CI katmanı.
- **Çıktı:** proje kökünde `warden-report/` klasörü (rapor + json + remediation + log).

---

## 4. Denetim Modülleri (denetimin kalbi)

Her modül **bulgu** üretir: `{id, başlık, şiddet(P0-P3), kategori, konum(file:line|endpoint), kanıt, etki, öneri, efor, otomatik-düzeltilebilir?}`.

### Modül A — Parity & Deployment Discovery (bu oturumun otomasyonu)
Pasif/read-only. Local ↔ production farkını kanıtlar.
- **A1 Kod parity:** prod git HEAD vs ana dal, kaç commit geride, çalışma ağacı kirli mi (elle düzenleme = drift).
- **A2 Şema/DB parity:** "şema senkronu ŞU AN ne değiştirir?" — Prisma `migrate diff`, Django `makemigrations --check`, Rails `migrate:status`, Alembic `heads`. **Yıkıcı (DROP/rename) tespiti = veri kaybı uyarısı.**
- **A3 Çalışma zamanı tazeliği:** çalışan konteyner/process güncel koddan mı (oluşturulma tarihi vs son commit); healthy mi; crash-loop var mı. (`docker compose ps`, `pm2 list`, `systemctl status`, `kubectl get pods`).
- **A4 Altyapı config parity:** veriyi üreten ve servis eden servisler **aynı volume'u** paylaşıyor mu (bu oturumdaki signature-worker bug'ı); `.env` ↔ `.env.example` farkı (eksik prod env); port/depends_on/paylaşımlı storage.
- **A5 Operasyonel sağlık:** backup alınabiliyor mu **ve RESTORE drill** (sadece dump değil); disk/bellek (`df -h`, `free`); log/hata akışı; queue/worker (takılı job/DLQ); cron son-çalışma; **TLS/cert expiry**; DNS/tunnel sağlığı.
- **A6 Dış bağımlılık:** OAuth scope/consent durumu, 3rd-party key geçerliliği, webhook URL'leri canlıya mı bakıyor.

### Modül B — Statik Uygulama Güvenliği (SAST tarzı, pasif)
- **B1 Secret taraması:** kodda ve **git geçmişinde** hardcoded key/token/parola (gitleaks/trufflehog mantığı).
- **B2 Bağımlılık zafiyetleri:** `npm/pnpm audit`, `pip-audit`, `govulncheck`, OSV; eski/terk edilmiş paketler.
- **B3 Zayıf kripto:** standart-dışı AES (örn. CryptoJS EvpKDF — bu projede bulduğumuz gibi), zayıf hash (md5/sha1 parola), sabit IV, `Math.random()` token.
- **B4 Auth tasarım kusurları:** JWT localStorage'da mı, token TTL uzun mu, refresh rotation var mı, parola gücü (zxcvbn), session sabitleme.
- **B5 Authz / multi-tenancy:** cross-tenant erişim semantiği (bu projedeki OWNER bug'ı), IDOR pattern'leri, RLS/policy kapsamı, eksik yetki kontrolü.
- **B6 Injection yüzeyi:** ham SQL string concat, komut enjeksiyonu (`exec`/`child_process` kullanıcı girdisiyle), şablon/SSTI, path traversal, dosya upload doğrulaması.
- **B7 Web sertleştirme (kod):** CORS yapılandırması, security header middleware (helmet/HSTS), rate-limit varlığı, CSRF.
- **B8 Girdi doğrulama kapsamı:** şema doğrulama (Zod/Joi/pydantic) endpoint kapsamı; doğrulanmayan girdiler.
- **B9 Bilgi sızıntısı:** stack trace/verbose error production'da açık mı, debug flag, source map yayını.

### Modül C — Dinamik / DAST & Pentest (AKTİF — yalnızca Yetki Kapısı açıkken, §2)
- **C1 Açıkta kalan hassas dosya probe'u:** `/.env`, `/.git/config`, `/backup.sql`, `/.terraform.tfstate`, `/.s3cfg`, swagger/actuator, `.DS_Store` — bunlar 200 mu döndürüyor? (Bu oturumda Cloudflare loglarında tam bu botları gördük.)
- **C2 Security header & TLS doğrulama (canlı):** `curl -I` ile HSTS/CSP/X-Frame; TLS sürümü, cipher, cert expiry/zincir.
- **C3 Auth/erişim testi (non-destructive):** default credential denemesi (kısa, sabit liste), korumasız admin endpoint, IDOR spot-check (kendi iki test hesabıyla).
- **C4 Rate-limit & abuse:** kayıt/login rate-limit gerçekten devrede mi (düşük-hacimli, eşik testi), CAPTCHA bypass yüzeyi.
- **C5 Açık port/servis envanteri:** yalnızca allow-list host'larda, hafif port kontrolü (tam nmap taraması opsiyonel ve açıkça onaylı).
- **C6 Cookie/oturum güvenliği (canlı):** Secure/HttpOnly/SameSite bayrakları, token süresi.

> C modülü **asla** brute-force, DoS, veri exfiltrasyonu veya yıkıcı payload çalıştırmaz.

### Modül D — Uyum & Operasyonel Olgunluk
- **D1 Backup & DR:** yedek + **restore prosedürü test edilmiş mi**, retention, off-site.
- **D2 Gözlemlenebilirlik:** hata izleme (Sentry vb.) entegre mi, yapılandırılmış log, request korelasyon ID.
- **D3 Secret yönetimi:** vault/KMS mi yoksa düz `.env` mi; rotasyon.
- **D4 Veri koruma (GDPR/KVKK):** soft-delete, veri export, retention/temizleme, audit log kapsamı.
- **D5 CI/CD hijyeni:** pipeline var mı, test gate, lint, image tarama, branch koruması.
- **D6 Rollback yeteneği:** tanımlı geri-alma yolu, migration geri-alınabilirliği.

---

## 5. Çıktı Formatı (en değerli kısım)

`warden-report/` altına:

1. **`report.md`** — insan-okur yönetici özeti + şiddet sıralı bulgu listesi. Her bulgu:
   `[P0] Başlık · kategori · konum · kanıt · etki · önerilen düzeltme · efor`. Üstte bir **skor tablosu**
   (bu projedeki `canliya_alma.md` puan tablosu gibi: Auth, Güvenlik, Operasyon, Parity, vb. /10).
2. **`findings.json`** — makine-okur (CI'da gate olarak kullanılabilir; her bulgu stabil `id` + `fingerprint`).
3. **`remediation-playbook.md`** — ⭐ **her P0/P1 için kopyala-yapıştır Claude Code prompt'u.**
   Örn: "JWT'yi localStorage'dan httpOnly cookie'ye taşı: şu dosyalar (...), şu adımlar (...), şu testler (...)".
   Bu, kullanıcının "ayrı ajana ver, düzeltsin" akışını birebir besler.
4. **`warden-run.log`** — çalıştırılan her komutun denetim izi (şeffaflık/yetki kanıtı).
5. **`parity-report.md`** — Modül A'nın katman-katman ✅/🔴/⏳ tablosu (bu oturumdaki tablonun aynısı).

Şiddet ölçeği: **P0** (production blocker / aktif sömürülebilir) · **P1** (ilk müşteri öncesi) · **P2** (mimari borç) · **P3** (ölçek/iyileştirme). Bu projedeki `docs/canliya_alma.md` referans alınsın.

---

## 6. Önerilen Repo Yapısı

```
warden/
├─ SKILL.md                      # Claude Code skill manifesti + tetikleyiciler + güvenlik ilkeleri
├─ README.md                     # ne/neden/nasıl + §2 yetki ilkeleri en üstte
├─ warden.authz.example.yml      # yetki kapısı şablonu
├─ src/
│  ├─ core/                      # stack-agnostik orkestrasyon, bulgu modeli, rapor üretici
│  ├─ detect/                    # stack tespiti (package.json/prisma/manage.py/go.mod/compose)
│  ├─ modules/                   # A parity · B sast · C dast · D compliance (her biri bulgu üretir)
│  └─ adapters/                  # node-prisma-docker / node-generic / python / go / php / infra
├─ scripts/                      # read-only probe script'leri (paste-güvenli, kısa-satır deseni)
│  ├─ discovery/                 # git/schema-diff/container-age/volume/env-parity/backup-restore/tls
│  └─ dast/                      # exposed-file / headers / rate-limit (yetki-kapılı)
├─ templates/                    # report.md / remediation prompt şablonları
├─ test/
│  └─ fixtures/                  # kasıtlı-açıklı örnek projeler (regression: bulguları yakalıyor mu)
└─ docs/
   └─ CHECKS.md                  # tüm kontrollerin kataloğu (id, açıklama, şiddet, otomatik mi)
```

---

## 7. Yapım Fazları (ajan bu sırayla ilerlesin, her fazda onay alsın)

**Faz 0 — İskelet & Güvenlik çerçevesi**
- Repo + `SKILL.md` + `README` (§2 ilkeleri üstte) + `warden.authz.example.yml`.
- Bulgu veri modeli + şiddet ölçeği + boş rapor üretici.
- **Kabul:** `warden` çağrılınca yetki kapısını okur, pasif modda boş ama geçerli rapor üretir.

**Faz 1 — Stack tespiti + Modül A (Parity, pasif)**
- `detect/` ile stack belirle; first-class adaptör Node/Prisma/Docker.
- A1–A6 read-only kontrolleri (script'ler **paste-güvenli kısa-satır** desenli — bu oturumdaki `/tmp/dc.sh` dersi).
- **Kabul:** Node/Prisma/Docker bir projede A modülü ✅/🔴 tablosu üretir; bu oturumdaki signature-worker volume bug'ını yakalar.

**Faz 2 — Modül B (Statik güvenlik, pasif)**
- B1–B9; mevcut araçları sarmala (gitleaks/trufflehog, npm/pip/govuln audit, semgrep kuralları).
- **Kabul:** fixtures'taki CryptoJS, JWT-localStorage, OWNER-cross-tenant gibi açıkları yakalar.

**Faz 3 — Modül D (Uyum/operasyon, pasif)**
- D1–D6; çoğu kod/config okuması + Modül A operasyonel sinyalleri.
- **Kabul:** backup/Sentry/CI/soft-delete eksikliklerini bulgu olarak listeler.

**Faz 4 — Modül C (Aktif/DAST, YETKİ KAPILI)**
- C1–C6; **yalnızca** `warden.authz.yml` + allow-list ile. Rate-limited, non-destructive, audit-loglu.
- **Kabul:** yetki dosyası yokken hiç aktif istek atmaz; varken yalnızca allow-list host'lara, exposed-file/header/TLS bulgularını üretir.

**Faz 5 — Rapor + Remediation Playbook**
- `report.md` + `findings.json` + `remediation-playbook.md` (Claude Code prompt'ları) + skor tablosu.
- **Kabul:** her P0/P1 için uygulanabilir bir Claude Code prompt'u içerir.

**Faz 6 — Paketleme + Diğer stack adaptörleri**
- Kurulum akışı (`.claude/skills/` kopyası veya `init` komutu); Python/Go/PHP/infra adaptörleri.
- `docs/CHECKS.md` tam katalog.
- **Kabul:** ikinci bir stack'te (örn. Django) en az A+B+D çalışır.

---

## 8. Doğrulama Stratejisi
- `test/fixtures/` altında **kasıtlı açıklı** mini projeler (vulnerable-by-design). Her kontrolün
  ilgili açığı yakaladığını doğrulayan regresyon testi.
- Gerçek dünya dumb-test: skill'i bu iş emrini doğuran SaaS tipi bir projede koştur; ürettiği
  bulgular elle bilinen açıklarla örtüşüyor mu (CryptoJS, JWT-localStorage, OWNER, volume-mismatch).
- **False-positive disiplini:** her bulgu kanıt (file:line / komut çıktısı) taşımalı; kanıtsız bulgu yok.

## 9. Teslim Kriterleri (Definition of Done)
- [ ] Pasif mod tek komutla çalışıp `warden-report/` üretiyor.
- [ ] Modül A bu oturumdaki tüm parity kontrollerini otomatik yapıyor.
- [ ] Modül B/D bilinen sınıf açıkları kanıtla yakalıyor.
- [ ] Modül C yetki kapısı olmadan ASLA aktif istek atmıyor; audit-log tutuyor.
- [ ] `remediation-playbook.md` her P0/P1 için Claude Code prompt'u veriyor.
- [ ] README §2 güvenlik ilkelerini en üstte taşıyor; çift-kullanım sorumluluğu açık.
- [ ] En az 2 stack adaptörü (Node/Prisma/Docker + bir tane daha).

---

## 10. AJANA İLK TALİMAT (kickoff)

> Yukarıdaki §0–§9'u oku. **Faz 0**'dan başla. Önce repo iskeletini, `SKILL.md`'yi, `README`'yi
> (§2 güvenlik/yetki ilkeleri en üstte), `warden.authz.example.yml`'yi ve bulgu veri modelini kur.
> Aktif/saldırgan hiçbir yetenek varsayılan çalışmamalı (Yetki Kapısı). Her fazın sonunda bana
> kabul kriterini göster, onay almadan sonraki faza geçme. Stack tespitinde first-class hedef:
> Node/TS + Prisma + Docker. Çıktıların nihai amacı: kanıtlı, şiddet-sıralı bulgular + her P0/P1
> için kopyala-yapıştır Claude Code remediation prompt'u. Şimdi Faz 0 için repo dosya ağacını ve
> `SKILL.md` taslağını üret.

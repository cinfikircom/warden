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
| B1 | Secret taraması (kod + commit'lenmiş .env): AWS/private key/Slack/GitHub token, sabit secret. Git geçmişi 🚧 | pasif | P0 | 2 | ✅ | gitleaks/trufflehog · OWASP A07 |
| B2 | Bağımlılık zafiyetleri: npm/pnpm audit (v6/v7 parser). pip-audit/govulncheck/OSV/Trivy Faz 6 | pasif | P1 | 2 | ✅ | OWASP A06 · OSV/Snyk/Trivy |
| B3 | Zayıf kripto: MD5/SHA1, ECB, CryptoJS EvpKDF, token için `Math.random()` | pasif | P1 | 2 | ✅ | OWASP A02 · ASVS 6.2 |
| B4 | Auth tasarımı: JWT localStorage (FE), uzun TTL. Refresh rotation/session fixation 🚧 | pasif | P1 | 2 | ✅ | OWASP A07 · ASVS 3.x |
| B5 | Authz / multi-tenancy: IDOR adayı (heuristic, düşük güven). Tam RLS/tenant semantiği manuel | pasif | P1 | 2 | 🚧 | OWASP A01 · API1 (BOLA) · ASVS 4.x |
| B6 | Injection: ham SQL concat, command injection, eval. SSTI/path traversal 🚧 | pasif | P0 | 2 | ✅ | OWASP A03 · semgrep |
| B7 | Web sertleştirme: CORS wildcard. helmet/HSTS/rate-limit/CSRF varlığı 🚧 | pasif | P1 | 2 | 🚧 | OWASP A05 |
| B8 | Girdi doğrulama kapsamı: Zod/Joi/pydantic endpoint kapsamı | pasif | P2 | 2 | ⏳ | ASVS 5.x |
| B9 | Bilgi sızıntısı: yanıtta stack trace. debug flag/source map 🚧 | pasif | P2 | 2 | 🚧 | OWASP A05 |

## Modül C — Dinamik / DAST & Pentest (AKTİF — yetki kapılı) · Faz 4

> ⚠ Tümü `warden.authz.yml` + allow-list gerektirir. Rate-limited, non-destructive, audit-loglu.

| ID | Kontrol | Tip | Şiddet | Faz | Durum | Eşleştirme |
|----|---------|-----|:------:|:---:|:-----:|------------|
| C1 | Açıkta kalan dosya probe: `/.env`, `/.git/config`, `/backup.sql`, `/.tfstate`, swagger/actuator (içerik doğrulayıcılı) | aktif | P0 | 4 | ✅ | OWASP A05 |
| C2 | Security header & TLS (canlı): HSTS/CSP/X-Frame/nosniff + TLS sürüm/cert (node:tls) | aktif | P1 | 4 | ✅ | Mozilla TLS · CIS |
| C3 | Korumasız admin paneli (GET, non-destructive). Default-cred DENEMESİ kasıtlı yapılmaz | aktif | P0 | 4 | ✅ | OWASP A01/A05 |
| C4 | Rate-limit eşik testi: düşük-hacim (5 GET) 429 alıyor mu | aktif | P1 | 4 | ✅ | OWASP API4 |
| C5 | Açık port/servis envanteri: hassas port listesi (Redis/Mongo/PostgreSQL…), yalnızca allow_port_scan ile | aktif | P2 | 4 | ✅ | CIS |
| C6 | Cookie güvenliği (canlı): Secure/HttpOnly/SameSite | aktif | P1 | 4 | ✅ | OWASP A05 · ASVS 3.4 |

## Modül D — Uyum & Operasyonel Olgunluk (pasif) · Faz 3

| ID | Kontrol | Tip | Şiddet | Faz | Durum | Eşleştirme |
|----|---------|-----|:------:|:---:|:-----:|------------|
| D1 | Backup & DR: yedek + restore drill (A5 sinyali); retention/off-site manuel | pasif | P2 | 3 | ✅ | ISO 27001 A.12 |
| D2 | Gözlemlenebilirlik: hata izleme (Sentry/Datadog/OTel) bağımlılık tespiti | pasif | P2 | 3 | ✅ | — |
| D3 | Secret yönetimi: vault/KMS/secret-manager bağımlılığı yoksa düz `.env` uyarısı | pasif | P2 | 3 | ✅ | ISO 27001 A.10 |
| D4 | Veri koruma (GDPR/KVKK): soft-delete (deletedAt) tespiti; export/retention manuel | pasif | P2 | 3 | ✅ | KVKK/GDPR |
| D5 | CI/CD hijyeni: pipeline + test/lint kapısı tespiti (GitHub/GitLab/Circle/Azure/Jenkins) | pasif | P2 | 3 | ✅ | SLSA |
| D6 | Rollback yeteneği: migration geri-alınabilirliği | pasif | P2 | 3 | ⏳ | — |
| **D7** | **PCI-DSS 4.0:** CVV saklama (P0 yasak), PAN saklama/maskeleme (P1) + **PCI checklist** (TLS/MFA/logging) | pasif | P0 | 3 | ✅ | PCI-DSS 4.0 |
| **D8** | **Privacy:** soft-delete + cookie-consent tespiti + **Privacy checklist** (silme/export/consent/retention) | pasif | P1 | 3 | ✅ | KVKK/GDPR |

## Modül E — OWASP Top 10 (2021) + ASVS eşleştirme (pasif) · Faz 2–3

OWASP açıklarını **açık isimle** bulur ve ASVS kontrollerine eşler. Raporda ASVS satırları
✔ Passed / ⚠ Partial / ✖ Failed gösterilir.

| ID | OWASP | Kontroller | Faz | Durum |
|----|-------|-----------|:---:|:-----:|
| E1 | A01 Broken Access Control | IDOR · Missing RBAC · Tenant Escape · Horizontal/Vertical Privilege Escalation | 2 | ⏳ |
| E2 | A02 Cryptographic Failures | MD5 · SHA1 · ECB · Fixed IV · Weak JWT Secret | 2 | ⏳ |
| E3 | A03 Injection | SQL · NoSQL · Command · LDAP · SSTI | 2 | ⏳ |
| E4 | A04 Insecure Design | tehdit modeli eksikliği, güvenli-olmayan akış | 2 | ⏳ |
| E5 | A05 Security Misconfiguration | Debug Enabled · Directory Listing · Swagger Public · Open Admin Panel | 2 | ⏳ |
| E6 | A06 Vulnerable Components | Snyk · OSV · Trivy (B2 ile paylaşımlı) | 2 | ⏳ |
| E7 | A07 Auth Failures | zayıf parola, session, MFA yok | 2 | ⏳ |
| E8 | A08 Software/Data Integrity | imzasız artifact, güvensiz deserialization | 2 | ⏳ |
| E9 | A09 Logging/Monitoring Failures | yetersiz log, alarm yok | 3 | ⏳ |
| E10 | A10 SSRF | sunucu-taraflı istek sahteciliği | 2 | ⏳ |
| E-ASVS | **OWASP ASVS Mapping** | bulgu referanslarından ✖/– checklist (risk/asvs.ts); compliance-report.md'de | 5 | ✅ |

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

## Modül API — OWASP API Security Top 10 (pasif + yetki kapılı aktif) · Faz 2/4

| ID | Kontrol | Faz | Durum |
|----|---------|:---:|:-----:|
| API1 | Broken Object Level Authorization (BOLA/IDOR) | 2 | ⏳ |
| API2 | Broken Authentication | 2 | ⏳ |
| API3 | Excessive Data Exposure | 2 | ⏳ |
| API4 | Lack of Resources & Rate Limiting | 4 | ⏳ |
| API5 | Broken Function Level Authorization | 2 | ⏳ |

## Modül FE — Frontend Security (React/Next vb., pasif) · Faz 2

| ID | Kontrol | Faz | Durum |
|----|---------|:---:|:-----:|
| FE-1 | localStorage/sessionStorage'da JWT/token | 2 | ✅ |
| FE-2 | CSP eksikliği / zayıf CSP | 2 | ⏳ |
| FE-3 | XSS sink'leri · `dangerouslySetInnerHTML` · Vue `v-html` | 2 | ✅ |
| FE-4 | Source map yayını (prod) | 2 | ⏳ |

## Modül AI — AI / LLM Security (pasif) · Faz 6+

| ID | Kontrol | Faz | Durum | Eşleştirme |
|----|---------|:---:|:-----:|------------|
| AI-1 | Prompt Injection yüzeyi (kullanıcı girdisi prompt'a birleşiyor) | + | ✅ | OWASP LLM01 |
| AI-2 | RAG/sistem-prompt sızıntısı (log/yanıt) | + | ✅ | OWASP LLM06 |
| AI-3 | Gömülü LLM API key (OpenAI/Anthropic/...) | + | ✅ | OWASP LLM02 |

> CLOUD/K8S/AI modülleri yalnızca ilgili dosyalar (IaC `.tf` · k8s manifest · AI SDK) bulununca koşar (gürültü önleme).

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
| Sarmalanan araçlar | Semgrep · Trivy · Gitleaks · OSV · Nuclei (yetki kapılı) | 2/4 | ⏳ |

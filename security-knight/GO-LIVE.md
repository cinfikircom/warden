# 🚀 Canlıya Alma Kontrol Listesi

`[x]` = bu pakette hazır/uygulandı · `[ ]` = senin projende bağlaman/yapman gerek.

## 🔴 Bloklayıcılar
- [x] **API auth altyapısı** — `server.mjs` tüm uçları `SK_ADMIN_TOKEN` ile Bearer korur; token yoksa
  yalnız 127.0.0.1 (dev-open). Üretim route'ları (`api-example/nextjs-routes.ts`) admin-oturumu ister.
- [x] **CORS wildcard kaldırıldı** — yalnız `SK_ALLOWED_ORIGIN`.
- [x] **Zırh durumu asla doğrudan yazılmaz** — yalnızca `warden-bridge.mjs`'in gerçek bir taramadan
  ürettiği `state/warden-posture.json` okunur; hiçbir uç "active" set etmez ("asla sahte gösterme").
- [x] **Girdi doğrulama + IP rate-limit + audit log** (`state/audit.log`).
- [x] **Otomatik düzeltme prosedürü PR-kapılı** — `packages/warden-skill/SKILL.md`: fingerprint
  doğrulaması geçmeden görev tamamlanmış sayılmaz; main'e asla doğrudan commit/merge yok.
- [ ] **Üretim API'sini uygulamana entegre et** — `nextjs-routes.ts`'i kopyala; `requireAdmin()`'i
  kendi Auth.js oturumuna bağla (şu an güvenli varsayılan: reddet). `server.mjs`'i public çalıştırma.
- [ ] **Serverless (Vercel) isen store'u değiştir** — dosya-yazımı kalıcı değil → `redisStore`
  (dosyada hazır iskelet) VE `POST /api/warden/scan`'i CI-tetikli hale getir (aşağıya bak — serverless
  fonksiyonda `pnpm warden scan` alt-süreci başlatmak güvenilir değildir).
- [ ] **Prod'a kod değişikliği için PR/onay kapısı** — zaten SKILL.md prosedürünün parçası; merge/deploy
  yine de elle onaylanmalı (en azından başta) — ajan asla otomatik merge etmez, ama bir insan onaylamalı.

## 🟠 Sertleştirme
- [x] `.gitignore` — `state/jobs.jsonl`, `state/audit.log`, `state/warden-posture.json`,
  `state/warden-gaps/`, `*.log`, `.env` repoya girmez.
- [x] `.env.example` — gerekli secret'lar dokümante (artık tek token: `SK_ADMIN_TOKEN`).
- [ ] **HTTPS/TLS** — panel + API yalnız https.
- [ ] **`AUTH_SECRET` + `SK_ADMIN_TOKEN`** — güçlü, secret-manager'da, rotasyonlu; repoda değil.
- [ ] **`/schedule` kill-switch + token bütçesi** — tam-otonom bir zamanlanmış ajan kurarsan
  (kuyruğu periyodik işlesin diye), kaçak-döngü + harcama sınırı koy.
- [ ] Panelin nihai yeri = hedef projen (şu an Warden repo dizininde duruyor).
- [ ] **`POST /api/warden/scan`'i serverless'te CI-tetikli yap** — bkz. `nextjs-routes.ts`'teki
  `triggerScanViaCi` iskeleti (bir GitHub Actions `workflow_dispatch` tetikler, sonucu polling'le izler).

## 🟡 Asıl iş (panelin ittiği)
Artık "kendi savunmanı inşa et" değil — **gerçek Warden bulgularını kapat**:
- [ ] `pnpm warden scan --target <proje>` düzenli koşsun (CI'da her PR'da, ya da `warden monitor`).
- [ ] Panelde her zırha bas → gerçek P0/P1 bulgularını gör → "🔧 Kendim düzelteceğim" ya da
  "🤖 Ajana kuyruğa al" ile kapat.
- [ ] Kuyruğu işleyecek bir yol seç: yarı-otonom (kullanıcı Claude Code'a "kuyruğu işle" der) ya da
  tam-otonom (`/schedule` ile zamanlanmış bulut ajanı) — bkz. `packages/warden-skill/SKILL.md`.

## Bana verince otomatik yapacaklarım
Hedef projenin yolu → kuyruktaki `warden-fix` görevlerini işlerim: bağımsız bulguları paralel
alt-ajanlarla düzeltirim, fingerprint bazlı öncesi/sonrası delta ile doğrularım, PR açarım.
İstersen `/schedule` ile tam-otonom bir koşucu da kurarım.

---
### Yerel dev'i çalıştırma
```bash
cp security-knight/.env.example security-knight/.env   # SK_ADMIN_TOKEN gir (opsiyonel)
node security-knight/server.mjs                          # http://127.0.0.1:8137/
# ya da repo kökünden: pnpm knight
```

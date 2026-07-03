# 🚀 Canlıya Alma Kontrol Listesi

`[x]` = bu pakette hazır/uygulandı · `[ ]` = senin projende bağlaman/yapman gerek.

## 🔴 Bloklayıcılar
- [x] **API auth altyapısı** — `server.mjs` artık `SK_ADMIN_TOKEN` ile tüm uçları Bearer korur; token yoksa yalnız 127.0.0.1 (dev-open). Üretim route'ları (`api-example/nextjs-routes.ts`) admin-oturumu + `/status` ajan-token ister.
- [x] **CORS wildcard kaldırıldı** — yalnız `SK_ALLOWED_ORIGIN`.
- [x] **`/status` ayrıcalığı** — posture'u yalnız ajan (`SK_AGENT_TOKEN`) yazabilir; herkes değil.
- [x] **Girdi doğrulama + IP rate-limit + audit log** (`state/audit.log`).
- [x] **Saldırı motoru yetki-kapısı** — attestation + host allow-list + e-posta onayı olmadan koşmaz.
- [ ] **Üretim API'sini uygulamana entegre et** — `nextjs-routes.ts`'i kopyala; `requireAdmin()`'i kendi Auth.js oturumuna bağla (şu an güvenli varsayılan: reddet). server.mjs'i public çalıştırma.
- [ ] **Serverless (Vercel) isen store'u değiştir** — dosya-yazımı kalıcı değil → `redisStore` (dosyada hazır iskelet).
- [ ] **Prod'a kod değişikliği için PR/onay kapısı** — ajan düzeltmeyi PR açar; merge/deploy elle onay (en azından başta).

## 🟠 Sertleştirme
- [x] `.gitignore` — `state/`, `*.log`, `attack.config.json`, `.env` repoya girmez.
- [x] `.env.example` — gerekli secret'lar dokümante.
- [ ] **HTTPS/TLS** — panel + API yalnız https.
- [ ] **`AUTH_SECRET` + `SK_*` token'ları** — güçlü, secret-manager'da, rotasyonlu; repoda değil.
- [ ] **Loop kill-switch + token bütçesi** — tam-otonom `/loop` kurarsan kaçak-döngü + harcama sınırı.
- [ ] Panelin nihai yeri = hedef projen (şu an Warden repo dizininde duruyor).

## 🟡 Asıl savunma işi (panelin ittiği)
- [ ] **`token1x`** — HMAC damgasına nonce + tek-kullanımlık (Redis/DB TTL) + e-posta/IP bağlama + süre 10–15dk.
- [ ] **`consttime`** — e-posta gönderimini kuyruğa al; bot/insan yolu sabit sürede dönsün.
- [ ] **`observ`** — bot-yakalama sayaçları + gerçek `/metrics` + ani-artış alarmı.
- [ ] **Backend test-modu kancası** — son isteğin bot mu sayıldığını / e-posta gitti mi dönen uç (honeypot & replay'i kara-kutu doğrulamak için).
- [ ] **Staging'e karşı `attack-harness.mjs` koş** — mevcut 3 aktif savunmayı gerçekten kanıtla.

## Bana verince otomatik yapacaklarım
Hedef projenin yolu + form URL'i + (varsa) test-kancası → `token1x` ve `consttime` düzeltmelerini
PR olarak uygular, saldırı motorunu staging'e koşar, geçerse posture'u `active` yaparım (şövalye Lv 5).
İstersen tam-otonom `/loop` koşucusunu da kurarım.

---
### Yerel dev'i çalıştırma
```bash
cp security-knight/.env.example security-knight/.env   # SK_ADMIN_TOKEN + SK_AGENT_TOKEN gir
node security-knight/server.mjs                          # http://127.0.0.1:8137/index.html
```
### Saldırı motoru (yalnız yetkili hedefe)
```bash
node security-knight/attack-harness.mjs --base https://staging.site.com \
  --request /api/auth/request-code --authorize --allow staging.site.com --ack-emails
```

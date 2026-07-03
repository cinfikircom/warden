/**
 * Güvenlik Şövalyesi — Saldırı & Test Motoru (bot simülasyonu, kara-kutu)
 * =========================================================================
 * Bir savunma "kuşanıldığında" ajan bunu koşarak GERÇEKTEN çalıştığını doğrular.
 *
 * ⚠ YETKİ: Yalnızca SANA AİT / test etmeye yetkili olduğun hedeflere koş (kendi staging/localhost).
 *   Non-destructive, düşük hacim. DoS/brute-force YOK.
 *
 * Kara-kutu ölçülebilir sinyaller (oracle-free tasarımı bile test eder):
 *   • timing        → sabit-süreli yanıt (consttime) ve enum paritesi açığını DOĞRUDAN ölçer
 *   • rate-limit    → eşik sonrası 429/engelleme
 *   • testHook      → (opsiyonel) backend test-modunda son isteğin bot mu sayıldığını/e-posta gitti mi söyler
 *                     → honeypot & replay & çok-hızlı sınıflandırmasını doğrular
 *
 * Çalıştır:  node attack-harness.mjs --config ./attack.config.json
 *            node attack-harness.mjs --base http://127.0.0.1:3000 --request /api/auth/request-code --email a@b.co
 * =========================================================================
 */

const DEFAULTS = {
  baseUrl: "http://127.0.0.1:3000",
  formPagePath: "/login",          // taze token+honeypot almak için
  requestPath: "/api/auth/request-code",
  fields: { email: "email", honeypot: "website", token: "ts" },
  registeredEmail: "known@example.com",
  unregisteredEmail: "nobody-xyz@example.com",
  testHookPath: null,              // ör. "/api/test/last-signal" → { classifiedBot, emailSent }
  rateLimit: { threshold: 5, burst: 8 },
  timing: { samples: 5, leakMs: 150 },
  // ⚠ YETKİ KAPISI — Warden mantığı. Bunlar geçerli olmadan saldırı KOŞULMAZ.
  authorization: {
    attestation: false,          // "bu hedefe ait/yetkiliyim" — koşmak için true olmalı
    authorizedTargets: [],       // izinli host allow-list (ör. ["staging.site.com","127.0.0.1"])
    acknowledgeEmails: false,     // "bu istekler gerçek doğrulama e-postası gönderebilir ve kota tüketir" onayı
  },
};

function parseArgs(argv){
  // Hem flag (--authorize) hem değer (--allow host) destekler.
  const o = {};
  for (let i=0;i<argv.length;i++){
    if (!argv[i].startsWith("--")) continue;
    const k = argv[i].slice(2);
    const next = argv[i+1];
    if (next === undefined || next.startsWith("--")) o[k] = true;
    else { o[k] = next; i++; }
  }
  return o;
}
async function loadConfig(){
  const a = parseArgs(process.argv.slice(2));
  let cfg = { ...DEFAULTS };
  if (a.config){ try { cfg = { ...cfg, ...JSON.parse(await (await import("node:fs/promises")).readFile(a.config,"utf8")) }; } catch(e){ console.error("config okunamadı:", e.message); } }
  if (a.base) cfg.baseUrl = a.base;
  if (a.request) cfg.requestPath = a.request;
  if (a.email) cfg.registeredEmail = a.email;
  // CLI ile yetki verme (config yerine): --authorize --allow host1,host2 --ack-emails
  if ("authorize" in a) cfg.authorization.attestation = true;
  if ("ack-emails" in a) cfg.authorization.acknowledgeEmails = true;
  if (a.allow) cfg.authorization.authorizedTargets = String(a.allow).split(",").map(s=>s.trim());
  return cfg;
}

/** Yetki kapısı: attestation + hedef allow-list'te + e-posta onayı yoksa REDDET. */
function checkAuthz(cfg){
  const az = cfg.authorization || {};
  let host = ""; try { host = new URL(cfg.baseUrl).hostname; } catch {}
  const problems = [];
  if (!az.attestation) problems.push("attestation yok (config.authorization.attestation=true veya --authorize)");
  if (!(az.authorizedTargets || []).includes(host))
    problems.push(`hedef '${host}' allow-list'te değil (config.authorization.authorizedTargets veya --allow ${host})`);
  if (!az.acknowledgeEmails) problems.push("e-posta onayı yok: bu testler GERÇEK doğrulama e-postası gönderip kota tüketebilir (acknowledgeEmails=true veya --ack-emails; ya da backend test-modunu kullan)");
  if (problems.length){
    console.error("\n⛔ YETKİ KAPISI KAPALI — saldırı koşulmadı. Eksikler:");
    for (const p of problems) console.error("   • " + p);
    console.error("\nYalnızca SANA AİT / yetkili hedeflere (staging/localhost), non-destructive koş.\n");
    process.exit(3);
  }
  console.log(`✓ Yetki: ${host} · e-posta onayı: evet · non-destructive`);
}

const med = arr => { const s=[...arr].sort((x,y)=>x-y); return s[Math.floor(s.length/2)] ?? 0; };

async function timedPost(url, payload){
  const t0 = performance.now();
  try {
    const r = await fetch(url, { method:"POST", headers:{ "content-type":"application/json" }, body: JSON.stringify(payload) });
    const body = await r.text().catch(()=> "");
    return { ms: performance.now()-t0, status: r.status, body, ok:true };
  } catch(e){ return { ms: performance.now()-t0, status:0, body:String(e.message), ok:false }; }
}

// Taze token/honeypot almaya çalış (form sayfasından). Bulamazsa boş döner.
async function freshToken(cfg){
  try {
    const r = await fetch(cfg.baseUrl + cfg.formPagePath);
    const html = await r.text();
    const m = html.match(new RegExp(`name=["']${cfg.fields.token}["'][^>]*value=["']([^"']+)`));
    return m ? m[1] : null;
  } catch { return null; }
}

function payload(cfg, { email, honeypot="", token=null }){
  const p = { [cfg.fields.email]: email };
  p[cfg.fields.honeypot] = honeypot;
  if (token) p[cfg.fields.token] = token;
  return p;
}

async function testHook(cfg){
  if (!cfg.testHookPath) return null;
  try { return await (await fetch(cfg.baseUrl + cfg.testHookPath)).json(); } catch { return null; }
}

/* --------------------- SALDIRILAR --------------------- */

async function attackTiming(cfg){
  // İnsan-benzeri vs honeypot-dolu (bot) yanıt sürelerini karşılaştır → sabit-süre açığı.
  const human=[], bot=[];
  for (let i=0;i<cfg.timing.samples;i++){
    const tok = await freshToken(cfg);
    human.push((await timedPost(cfg.baseUrl+cfg.requestPath, payload(cfg,{ email:`h${i}-${Date.now()}@ex.co`, token:tok }))).ms);
    bot.push((await timedPost(cfg.baseUrl+cfg.requestPath, payload(cfg,{ email:`b${i}-${Date.now()}@ex.co`, honeypot:"http://spam", token:tok }))).ms);
  }
  const dh=med(human), db=med(bot), delta=Math.abs(dh-db);
  const passed = delta <= cfg.timing.leakMs;
  return { name:"Zamanlama sızıntısı (Zaman Peçesi)", key:"consttime", passed,
    detail:`insan≈${dh|0}ms, bot≈${db|0}ms, fark=${delta|0}ms (eşik ${cfg.timing.leakMs}ms). ${passed?"Süreler ayırt edilemez ✓":"Bot yolu ölçülebilir biçimde farklı — zamanlama oracle'ı ✗"}` };
}

async function attackRateLimit(cfg){
  const codes=[];
  for (let i=0;i<cfg.rateLimit.burst;i++){
    const tok = await freshToken(cfg);
    codes.push((await timedPost(cfg.baseUrl+cfg.requestPath, payload(cfg,{ email:"flood@ex.co", token:tok }))).status);
  }
  const blocked = codes.filter(c=>c===429 || c===403).length;
  const passed = blocked > 0;
  return { name:"Rate-limit taşkını (Sur Duvarı)", key:"rlip", passed,
    detail:`${cfg.rateLimit.burst} istek → durumlar [${codes.join(",")}], engellenen=${blocked}. ${passed?"Eşik sonrası engelleniyor ✓":"Hiç engelleme yok ✗"}` };
}

async function attackEnumParity(cfg){
  const reg=[], unreg=[];
  for (let i=0;i<cfg.timing.samples;i++){
    const t1=await freshToken(cfg), t2=await freshToken(cfg);
    reg.push(await timedPost(cfg.baseUrl+cfg.requestPath, payload(cfg,{ email:cfg.registeredEmail, token:t1 })));
    unreg.push(await timedPost(cfg.baseUrl+cfg.requestPath, payload(cfg,{ email:cfg.unregisteredEmail, token:t2 })));
  }
  const dR=med(reg.map(x=>x.ms)), dU=med(unreg.map(x=>x.ms));
  const sameStatus = reg[0].status === unreg[0].status;
  const sameBody = reg[0].body === unreg[0].body;
  const dt = Math.abs(dR-dU);
  const passed = sameStatus && sameBody && dt <= cfg.timing.leakMs;
  return { name:"E-posta enumerasyon paritesi (İki Yüz Maskesi)", key:"enum", passed,
    detail:`kayıtlı≈${dR|0}ms/${reg[0].status} vs kayıtsız≈${dU|0}ms/${unreg[0].status}, gövde-aynı=${sameBody}. ${passed?"Ayırt edilemez ✓":"Fark var — enumerasyon mümkün ✗"}` };
}

async function attackHoneypotAndReplay(cfg){
  // testHook varsa: honeypot-dolu & replay isteklerinin bot sayıldığını + e-posta gitmediğini doğrula.
  const hook = cfg.testHookPath;
  if (!hook) return [{ name:"Honeypot & Replay sınıflandırması", key:"honeypot", passed:null,
    detail:"testHook tanımlı değil — oracle-free tasarımda kara-kutu doğrulanamaz. Backend test-modunda son sinyali açığa çıkaran bir uç ekle (bkz. AGENT-RUNNER.md)." }];
  const out=[];
  // honeypot
  const tok1 = await freshToken(cfg);
  await timedPost(cfg.baseUrl+cfg.requestPath, payload(cfg,{ email:"hp@ex.co", honeypot:"http://x", token:tok1 }));
  const s1 = await testHook(cfg);
  out.push({ name:"Honeypot (Gölge Pelerini)", key:"honeypot", passed: !!(s1 && s1.classifiedBot && !s1.emailSent),
    detail:`son sinyal: ${JSON.stringify(s1)}` });
  // replay
  const tok2 = await freshToken(cfg);
  await timedPost(cfg.baseUrl+cfg.requestPath, payload(cfg,{ email:"rp@ex.co", token:tok2 }));
  const r2 = await timedPost(cfg.baseUrl+cfg.requestPath, payload(cfg,{ email:"rp@ex.co", token:tok2 }));
  const s2 = await testHook(cfg);
  out.push({ name:"Damga tekrarı / replay (Kırılmaz Mühür)", key:"token1x",
    passed: !!(s2 && !s2.emailSent), detail:`ikinci gönderim sinyali: ${JSON.stringify(s2)} (status ${r2.status})` });
  return out;
}

async function attackPositivePath(cfg){
  // #2 DOSTU VURMA: meşru insan-benzeri gönderim BAŞARILI olmalı (sessizce düşmemeli).
  // Aşırı-agresif savunma gerçek kullanıcıyı kaybeder — ve sessiz tasarımda bunu hiç duymazsın.
  const n = cfg.timing.samples; let ok = 0, blocked = 0; const hook = cfg.testHookPath;
  for (let i = 0; i < n; i++){
    const tok = await freshToken(cfg);
    const r = await timedPost(cfg.baseUrl + cfg.requestPath, payload(cfg, { email:`real${i}-${Date.now()}@ex.co`, honeypot:"", token:tok }));
    const s = hook ? await testHook(cfg) : null;
    const passed = hook ? !!(s && !s.classifiedBot && s.emailSent) : (r.status >= 200 && r.status < 300);
    passed ? ok++ : blocked++;
  }
  const passed = blocked === 0;
  return { name:"Dostu vurma / False-positive (İki Yüz Maskesi altı)", key:"friendlyfire", passed,
    detail:`${n} meşru gönderimden ${ok} geçti, ${blocked} bloklandı${hook ? "" : " (testHook yok → yalnız HTTP durumu)"}. ${passed ? "Gerçek kullanıcı engellenmiyor ✓" : "⚠ Meşru kullanıcı sessizce düşüyor — DOSTU VURMA (dönüşüm kaybı)"}` };
}

/* --------------------- KOŞUCU --------------------- */

async function run(){
  const cfg = await loadConfig();
  checkAuthz(cfg);
  console.log(`\n⚔️  Saldırı & Test — hedef: ${cfg.baseUrl}${cfg.requestPath}\n${"─".repeat(56)}`);
  const results = [];
  results.push(await attackPositivePath(cfg));   // #2 dostu vurma (önce: gerçek kullanıcı geçmeli)
  results.push(await attackTiming(cfg));
  results.push(await attackRateLimit(cfg));
  results.push(await attackEnumParity(cfg));
  results.push(...await attackHoneypotAndReplay(cfg));

  for (const r of results){
    const icon = r.passed === true ? "✅" : r.passed === false ? "❌" : "⚠️ ";
    console.log(`${icon} ${r.name}\n     ${r.detail}`);
  }
  const fails = results.filter(r => r.passed === false);
  const na = results.filter(r => r.passed === null);
  console.log(`${"─".repeat(56)}\nÖZET: ${results.filter(r=>r.passed===true).length} geçti · ${fails.length} kaldı · ${na.length} n/d`);
  // Makine-okur çıktı (ajan bunu okuyup posture'u güncelleyebilir).
  console.log("\nJSON:" + JSON.stringify({ target: cfg.baseUrl, results, failedKeys: fails.map(f=>f.key) }));
  process.exit(fails.length ? 1 : 0);
}

run().catch(e => { console.error("harness hata:", e); process.exit(2); });

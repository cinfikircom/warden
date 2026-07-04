/**
 * GÜVENLİK ŞÖVALYESİ — genel widget (framework-agnostik ES module)
 * =========================================================================
 * Kullanım (README'de detay):
 *   import { mountSecurityKnight } from "./knight.js";
 *   import { WARDEN_POSTURE } from "./posture-warden.js";
 *   mountSecurityKnight(document.querySelector("#kok"), { posture: WARDEN_POSTURE, endpoint: "/api/warden/posture", mode:"live" });
 *
 * Zırh durumunun GERÇEK kaynağı backend'dir (endpoint) — `warden-bridge.mjs`'in gerçek bir
 * Warden taramasından ürettiği durum. "Kuşan" gerçek bir tarama tetikler (bkz. openWardenDrawer);
 * hiçbir buton doğrudan "active" yazmaz. Bir zırh eklemek = posture-warden.js'e bir nesne
 * (Warden modül id'siyle eşleşen `key`, SVG parçası dahil) — bu dosya değişmez.
 * =========================================================================
 */

const FACTOR = { active:1, partial:0.6, open:0, optional:0 };
const TAG = { active:"KUŞANILDI", partial:"KISMİ", open:"EKSİK", optional:"KALINTI" };

/* ---------- SAF ÇEKİRDEK (test edilebilir, DOM'suz) ---------- */

export function computeScore(layers){
  const core = layers.filter(l => l.weight > 0);
  const tot = core.reduce((a,l)=>a+l.weight,0) || 1;
  const earn = core.reduce((a,l)=>a+l.weight*(FACTOR[l.status] ?? 0),0);
  return Math.round(earn/tot*100);
}

// --- ÖLÇÜLEN duruş (#1): doğrulama-duyarlı ---
// aktif+verified=1 · aktif+claimed(iddia, kanıtsız)=0.6 · aktif+failed(düştü)=0
const VER_FACTOR = { verified:1, claimed:0.6, failed:0 };

/** Aktif bir katmanın doğrulama durumu. Doğrulama verisi yoksa "claimed" (iddia). Aktif değilse null. */
export function verState(layer, verification){
  if (layer.status !== "active") return null;
  const v = verification && verification[layer.key];
  return (v && v.state) || "claimed";
}

/** Skorun ÖLÇÜLEN hali: aktif ama doğrulanmamış savunma tam puan almaz. */
export function computeMeasuredScore(layers, verification){
  const core = layers.filter(l => l.weight > 0);
  const tot = core.reduce((a,l)=>a+l.weight,0) || 1;
  const earn = core.reduce((a,l)=>{
    if (l.status === "active") return a + l.weight * (VER_FACTOR[verState(l, verification)] ?? 0.6);
    return a + l.weight * (FACTOR[l.status] ?? 0);
  }, 0);
  return Math.round(earn/tot*100);
}
export function rankOf(score, ranks){
  let r = ranks[0];
  for (const x of ranks) if (score >= x.min) r = x;
  return r;
}
export function nextRank(score, ranks){ return ranks.find(x => x.min > score) || null; }

/**
 * Şövalye SVG'sini kurar: base + zırh parçaları (z sırasıyla).
 * Doğrulama-duyarlı: verified→katı zırh · claimed→HAYALET zırh (yarı-saydam) · failed→zırh DÜŞTÜ (zayıflık) · open→zayıflık.
 */
export function buildKnightSVG(posture, layers, verification, opts = {}){
  const BASE_Z = opts.baseZ ?? 5;
  const active = new Set(layers.filter(l => l.status === "active").map(l => l.key));
  const parts = [{ z: BASE_Z, svg: posture.base }];
  for (const l of layers){
    if (l.requires && !active.has(l.requires)) continue; // bağımlı parça (ör. çatlak yalnız kalkan varsa)
    const z = l.z ?? BASE_Z;
    if (l.status === "active" && l.svg){
      const vs = verState(l, verification);
      if (vs === "failed"){ if (l.weakSvg) parts.push({ z, svg: l.weakSvg }); }            // zırh düştü
      else if (vs === "claimed") parts.push({ z, svg: `<g class="sk-ghost-armor">${l.svg}</g>` }); // hayalet
      else parts.push({ z, svg: l.svg });                                                   // verified: katı
    } else if (l.status === "open" && l.weakSvg){
      parts.push({ z, svg: l.weakSvg });
    }
  }
  parts.sort((a,b)=>a.z-b.z);
  const inner = parts.map(p=>p.svg).join("");
  return `<svg viewBox="0 0 150 210" width="150" height="210" class="knight-svg" aria-label="güvenlik şövalyesi">${inner}</svg>`;
}

/** Aktif zırh sayısı / toplam çekirdek zırh (dolam göstergesi). */
export function equippedCount(layers){
  const core = layers.filter(l => l.weight > 0);
  return { on: core.filter(l => l.status === "active").length, total: core.length };
}

/* ---------- DOM KATMANI (mount) ---------- */

const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[c]));

export function mountSecurityKnight(target, options = {}){
  if (!target) throw new Error("mountSecurityKnight: hedef eleman gerekli.");
  const posture = options.posture;
  if (!posture) throw new Error("mountSecurityKnight: options.posture gerekli.");
  const mode = options.mode || (options.endpoint ? "live" : "demo");
  const assetBase = options.assetBase || "assets"; // gerçekçi şövalye görselleri (knight-lv1..6.png)
  const loopEnabled = mode === "live" && (options.loopEndpoint || options.endpoint); // Phase 4: tek döngü
  const loopUrl = options.loopEndpoint || "/api/loop/run";

  const jobsUrl = options.jobsEndpoint || "/api/warden/jobs";
  // Gerçek-taramaya-dayalı akış (Warden-tarama boyutları için; bkz. plan Bölüm D).
  const scanUrl = options.scanEndpoint || "/api/warden/scan";
  const gapsUrl = options.gapsEndpoint || "/api/warden/gaps";
  const fixQueueUrl = options.fixQueueEndpoint || "/api/warden/fix-queue";
  const SEVERITY_EMOJI = { P0:"🔴", P1:"🟠", P2:"🟡", P3:"⚪" };

  // Durum kopyası (canlı modda backend ile güncellenir).
  const state = {
    layers: posture.layers.map(l => ({ ...l })),
    relics: (posture.relics || []).map(l => ({ ...l })),
    metrics: options.metrics || posture.metrics || {},
    verification: {},   // key → { state:"verified|claimed|failed", method, detail } (backend'den)
    pendingKeys: new Set(), // kuyrukta "queued" bekleyen görevlerin key'leri — arka planda iş sürüyor göstergesi
    original: null,
  };

  // Üretim auth'una uyumlu fetch: oturum çerezi + opsiyonel Bearer token.
  function apiFetch(url, opts = {}){
    const headers = { accept: "application/json", ...(opts.headers || {}) };
    if (options.authToken) headers.authorization = `Bearer ${options.authToken}`;
    return fetch(url, { credentials: "include", ...opts, headers });
  }

  async function loadPosture(){
    if (!options.endpoint) return;
    try{
      const res = await apiFetch(options.endpoint);
      const data = await res.json(); // { statuses: { key: "active"|... }, metrics?: {...} }
      const map = data.statuses || data;
      for (const l of state.layers) if (map[l.key]) l.status = map[l.key];
      for (const l of state.relics) if (map[l.key]) l.status = map[l.key];
      if (data.metrics) state.metrics = data.metrics;
      if (data.verification) state.verification = data.verification.results || data.verification;
    }catch(e){ /* offline/demo → gömülü posture */ }
  }

  // Kuyrukta bekleyen ("queued") görevler → "arka planda işleniyor" göstergesi.
  // Ajan bir görevi tamamlayıp posture'u "active" yapınca, o key artık pending sayılmaz
  // (durum gerçeğin tek kaynağıdır); job kaydı kuyrukta kalsa bile panel doğru gösterir.
  async function loadJobs(){
    if (mode !== "live") return;
    try{
      const res = await apiFetch(jobsUrl);
      const data = await res.json();
      const pending = new Set();
      for (const j of (data.jobs || [])) if (j.state === "queued") pending.add(j.key || j.module);
      state.pendingKeys = pending;
    }catch(e){ /* backend yok — pending bilinmiyor, sessizce geç */ }
  }

  // Posture + kuyruğu birlikte tazele, sonra çiz. `announce`=true ise arka planda tamamlanan
  // (queued/open/partial → active) geçişleri kutlar — kullanıcı butona bastıktan sonra ekrandan
  // ayrılıp geri dönse bile, ya da ajan kuyruğu terminalden işlese bile zırh kuşanma anı KAÇMAZ.
  let baseline = null; // önceki turdaki key → status (ilk yüklemede null → sahte kutlama yok)
  async function syncAndRender(announce){
    const prevBaseline = baseline;
    await Promise.all([loadPosture(), loadJobs()]);
    render();
    const cur = {};
    for (const l of state.layers) cur[l.key] = l.status;
    for (const l of state.relics) cur[l.key] = l.status;
    if (announce && prevBaseline){
      for (const l of state.layers){
        if (prevBaseline[l.key] && prevBaseline[l.key] !== "active" && l.status === "active"){
          const after = computeMeasuredScore(state.layers, state.verification);
          flash();
          toast(`${l.icon} ${l.name} kuşanıldı — arka plandaki iş tamamlandı! Ölçülen güç ${after}/100.`);
        }
      }
    }
    baseline = cur;
  }

  function celebrate(layer, before, after){
    const stage = target.querySelector(".sk-stage");
    if (stage){ const f = stage.querySelector(".sk-flash"); if (f){ f.classList.remove("go"); void f.offsetWidth; f.classList.add("go"); } }
    const ranks = posture.ranks;
    const lvUp = rankOf(after, ranks).lv > rankOf(before, ranks).lv;
    toast(`${layer.icon} ${layer.name} kuşanıldı! Güç ${before} → ${after}. ${lvUp ? "⭐ Rütbe atladın!" : "Şövalyen güçlendi."}`);
  }

  function toast(msg){
    let t = target.querySelector(".sk-toast");
    if (!t){ t = document.createElement("div"); t.className = "sk-toast"; target.appendChild(t); }
    t.textContent = msg; t.classList.add("show");
    clearTimeout(toast._); toast._ = setTimeout(()=>t.classList.remove("show"), 2800);
  }

  // Phase 4 — tek döngü: Warden taraması → köprü → doğrulama; sonra panel kendini yeniler.
  let looping = false;
  async function tryLoop(){
    if (looping) return; looping = true;
    toast("🔄 Döngü başladı: Warden taraması → köprü → doğrulama…");
    try { await apiFetch(loopUrl, { method:"POST", headers:{ "content-type":"application/json" }, body:"{}" }); }
    catch { toast("Backend'e ulaşılamadı — döngü tetiklenemedi."); looping = false; return; }
    let tries = 0;
    const iv = setInterval(async () => {
      const before = computeMeasuredScore(state.layers, state.verification);
      await loadPosture(); render();
      const after = computeMeasuredScore(state.layers, state.verification);
      if (after !== before) toast(`Şövalye güncellendi — ölçülen güç ${after}/100.`);
      if (++tries >= 10){ clearInterval(iv); looping = false; }
    }, 2500);
  }

  function snapshot(){
    if (!state.original) state.original = { st: state.layers.map(x => x.status),
      ver: JSON.parse(JSON.stringify(state.verification)) };
    const rb = target.querySelector(".sk-reset"); if (rb) rb.style.display = "";
  }
  function flash(){ const st = target.querySelector(".sk-stage"); const f = st && st.querySelector(".sk-flash");
    if (f){ f.classList.remove("go"); void f.offsetWidth; f.classList.add("go"); } }
  // Genel amaçlı çekirdek: bu widget'ı kendi posture'unla (kendi self-check/attack-test'inle)
  // entegre eden başka projeler için — "aktif ama kanıtsız" (hayalet) zırhı nasıl doğrularsın.
  const verifyQuestOf = l => ({
    why: l.verify?.needsTestHook
      ? "Aktif ama kara-kutu KANITLANAMIYOR (oracle-free tasarım — bot da insanla aynı yanıtı görür). Doğrulamak için backend test-modu kancası gerekir."
      : "Aktif ama henüz gerçek bir testle kanıtlanmadı — bu yüzden hayalet zırh (tam puan almaz).",
    steps: [
      "Backend test-modu kancası ekle: son isteğin gerçekten bloklandığını/geçtiğini dönen bir uç.",
      "O uca karşı gerçek bir doğrulama testi (self-check ya da yetkili saldırı testi) koş.",
      "Sonucu backend'in verification endpoint'ine yaz → hayalet katılaşır, ölçülen güç yükselir.",
    ],
    acceptance: ["Doğrulama testi geçiyor → zırh KATI (doğrulandı), hayalet değil"],
  });

  // Gerçek Warden bulgularını (şablon değil) çekmecede listeler.
  function renderGapsList(findings){
    if (!findings.length) return `<div class="sk-note">Bu boyutta P0/P1 bulgu yok — köprü zaten "active" işaretlemiş olmalı.</div>`;
    return `<div class="sk-block"><div class="sk-block-h"><h4>🔎 Gerçek eksikler (${findings.length})</h4></div>
      <ol class="sk-gaps">${findings.map(f => `<li>
        <b>${SEVERITY_EMOJI[f.severity] || ""} [${esc(f.severity)}] ${esc(f.title)}</b>
        ${f.evidence?.length ? `<div class="sk-muted">${f.evidence.map(e => esc(`${e.source}${e.location ? ":" + e.location : ""}`)).join(" · ")}</div>` : ""}
        <div class="sk-ds">${esc(f.recommendation || "")}</div>
      </li>`).join("")}</ol></div>`;
  }

  // Bir Warden boyutu için: hemen gerçek tarama tetikle, sonra gaps'i yokla (tıpkı tryLoop gibi).
  async function scanAndPollGaps(key, onUpdate){
    try { await apiFetch(scanUrl, { method:"POST", headers:{ "content-type":"application/json" }, body: JSON.stringify({ module:key }) }); }
    catch { onUpdate(null, "Backend'e ulaşılamadı — tarama tetiklenemedi."); return; }
    let tries = 0;
    const iv = setInterval(async () => {
      try{
        const r = await apiFetch(`${gapsUrl}?module=${encodeURIComponent(key)}`);
        const data = await r.json();
        if (data.findings && data.findings.length >= 0 && !data.note){ clearInterval(iv); onUpdate(data.findings, null); return; }
      }catch{ /* henüz hazır değil */ }
      if (++tries >= 10){ clearInterval(iv); onUpdate([], "Tarama zaman aşımına uğradı — 'Yeniden tara & doğrula' ile tekrar dene."); }
    }, 1500);
  }

  // "Ajana kuyruğa al": zengin bir warden-fix görevi kuyruğa girer; SKILL.md prosedürü işler.
  async function tryFixQueue(key){
    const l = state.layers.find(x => x.key === key); if (!l) return;
    try {
      await apiFetch(fixQueueUrl, { method:"POST", headers:{ "content-type":"application/json" }, body: JSON.stringify({ module:key }) });
      toast(`🤖 ${l.name} kuyruğa alındı — ajan taze tarayıp paralel düzeltecek, doğrulanınca zırh kendiliğinden kuşanır.`);
    } catch { toast("Backend'e ulaşılamadı — kuyruğa alınamadı."); }
    state.pendingKeys.add(key); // iyimser: sunucu tarafında iş başladı, sonraki poll gerçek durumu teyit eder
    render();
    closeDrawer();
  }

  // Hayalet zırhı doğrula (kanıtla).
  async function tryVerify(key){
    const l = state.layers.find(x => x.key === key); if (!l) return;
    const before = computeMeasuredScore(state.layers, state.verification);
    if (mode === "demo"){
      snapshot();
      state.verification[key] = { state:"verified", method:"önizleme", detail:"Önizleme: doğrulandı." };
      const after = computeMeasuredScore(state.layers, state.verification);
      render(); flash();
      toast(`🔍 ${l.name} DOĞRULANDI — hayalet zırh katılaştı! Ölçülen güç ${before} → ${after}.`);
    } else {
      toast("🔍 Doğrulama çalıştırılıyor… (self-check + saldırı testi)");
      const verifyUrl = options.verifyEndpoint || (options.endpoint ? options.endpoint.replace(/posture\/?$/, "verify") : null);
      try { if (verifyUrl) await apiFetch(verifyUrl, { method:"POST", headers:{ "content-type":"application/json" }, body: JSON.stringify({ key }) }); } catch {}
      await loadPosture(); render();
      toast(verState(l, state.verification) === "verified"
        ? `✅ ${l.name} doğrulandı — zırh katılaştı.`
        : "Henüz kanıtlanamadı — test-kancası ekleyip saldırı motorunu staging'e koş.");
    }
    closeDrawer();
  }

  async function tryEquip(key){
    const l = state.layers.find(x => x.key === key);
    if (!l) return;
    const before = computeScore(state.layers);
    if (mode === "demo"){
      snapshot();
      l.status = "active";
      const after = computeScore(state.layers);
      render(); celebrate(l, before, after);
    } else {
      // CANLI: görevi backend kuyruğuna düşür (ajan işleyecek), sonra durumu yeniden oku.
      const equipUrl = options.equipEndpoint
        || (options.endpoint ? options.endpoint.replace(/posture\/?$/, "equip") : "/api/security/equip");
      try {
        const r = await apiFetch(equipUrl, { method:"POST", headers:{ "content-type":"application/json" },
          body: JSON.stringify({ key }) });
        const data = await r.json().catch(()=>({}));
        toast(data.queued === false ? "Bu güç zaten aktif."
          : `🗡️ Görev kuyruğa alındı: ${l.name}. Ajan düzeltmeyi uygulayıp saldırı testini koşacak — durumu aşağıda "işleniyor" olarak göreceksin.`);
      } catch { toast("Backend'e ulaşılamadı — görev kuyruğa alınamadı."); }
      await Promise.all([loadPosture(), loadJobs()]);
      const after = computeScore(state.layers);
      render();
      if (state.layers.find(x=>x.key===key).status === "active") celebrate(l, before, after);
    }
    closeDrawer();
  }

  function openDrawer(key, kind){
    const l = state.layers.find(x => x.key === key);
    const isVerify = kind === "verify";
    const isWardenEquip = !isVerify && l.kind === "warden" && mode === "live";

    if (isWardenEquip){ openWardenDrawer(l, key); return; }

    const q = isVerify ? verifyQuestOf(l) : (l.quest || {});
    const actLabel = isVerify
      ? (mode === "demo" ? "🔍 Doğrula (önizleme)" : "🔍 Doğrulamayı çalıştır")
      : (mode === "demo" ? "⚒ Kuşan (önizleme)" : "✓ Kuşandım — doğrula");
    const wrap = document.createElement("div");
    wrap.className = "sk-drawer";
    wrap.innerHTML = `
      <div class="sk-drawer-card">
        <button class="sk-x" aria-label="kapat">✕</button>
        <div class="sk-drawer-h"><span class="sk-drawer-ic">${l.icon}</span>
          <div><b>${esc(l.name)}</b><div class="sk-muted">${esc(l.realName || "")} · +${l.weight} güç</div></div></div>
        <p class="sk-why">${esc(q.why || l.desc)}</p>
        ${q.steps ? `<div class="sk-block">
          <div class="sk-block-h"><h4>⚒ Nasıl kuşanılır</h4><button class="sk-copy" type="button">📋 Adımları kopyala</button></div>
          <ol>${q.steps.map(s=>`<li>${esc(s)}</li>`).join("")}</ol></div>` : ""}
        ${q.acceptance ? `<div class="sk-block"><div class="sk-block-h"><h4>✓ Kabul kriteri</h4></div>
          <ul>${q.acceptance.map(s=>`<li>${esc(s)}</li>`).join("")}</ul></div>` : ""}
        <div class="sk-drawer-actions">
          <button class="sk-btn sk-verify">${actLabel}</button>
          <button class="sk-btn ghost sk-cancel">Kapat</button>
        </div>
        ${mode === "demo" ? `<div class="sk-tip">Önizleme: gerçek güç için düzeltmeyi kodda uygula; canlı modda backend "active" deyince zırh kalıcı belirir.</div>` : ""}
      </div>`;
    target.appendChild(wrap);
    const close = () => closeDrawer();
    wrap.querySelector(".sk-x").onclick = close;
    wrap.querySelector(".sk-cancel").onclick = close;
    wrap.onclick = e => { if (e.target === wrap) close(); };
    wrap.querySelector(".sk-verify").onclick = () => (isVerify ? tryVerify(key) : tryEquip(key));
    const copyBtn = wrap.querySelector(".sk-copy");
    if (copyBtn) copyBtn.onclick = async () => {
      const text = (l.quest?.steps || []).map((s,i)=>`${i+1}. ${s}`).join("\n");
      try { await navigator.clipboard.writeText(text); toast("📋 Adımlar panoya kopyalandı"); }
      catch { toast("Kopyalanamadı — metni elle seçebilirsin"); }
    };
    drawerEsc = e => { if (e.key === "Escape") close(); };
    document.addEventListener("keydown", drawerEsc);
    toast(`🗺️ Görev açıldı: ${l.name} (+${l.weight} güç)`);
  }

  // Warden-tarama boyutu için çekmece: açılışta hemen gerçek tarama tetikler, gerçek bulguları
  // gösterir (şablon değil), "kendim düzelteceğim" / "ajana kuyruğa al" iki seçenek sunar.
  function openWardenDrawer(l, key){
    let lastFindings = null;
    const wrap = document.createElement("div");
    wrap.className = "sk-drawer";
    wrap.innerHTML = `
      <div class="sk-drawer-card">
        <button class="sk-x" aria-label="kapat">✕</button>
        <div class="sk-drawer-h"><span class="sk-drawer-ic">${l.icon}</span>
          <div><b>${esc(l.name)}</b><div class="sk-muted">${esc(l.realName || "")} · +${l.weight} güç</div></div></div>
        <p class="sk-why">${esc(l.desc)}</p>
        <div class="sk-gaps-body">🔎 Taranıyor… (gerçek Warden taraması çalışıyor)</div>
        <div class="sk-drawer-actions">
          <button class="sk-btn ghost sk-fixself">🔧 Kendim düzelteceğim</button>
          <button class="sk-btn sk-fixqueue">🤖 Ajana kuyruğa al (paralel düzelt)</button>
          <button class="sk-btn ghost sk-cancel">Kapat</button>
        </div>
      </div>`;
    target.appendChild(wrap);
    const close = () => closeDrawer();
    wrap.querySelector(".sk-x").onclick = close;
    wrap.querySelector(".sk-cancel").onclick = close;
    wrap.onclick = e => { if (e.target === wrap) close(); };
    wrap.querySelector(".sk-fixqueue").onclick = () => tryFixQueue(key);
    wrap.querySelector(".sk-fixself").onclick = async () => {
      const fps = (lastFindings || []).map(f => f.fingerprint).filter(Boolean);
      const text = `warden prompts --module ${key}${fps.length ? ` --fingerprint ${fps.join(",")}` : ""}\n(veya warden-report/remediation-playbook.md'deki ${key} bölümüne bak)`;
      try { await navigator.clipboard.writeText(text); toast("📋 Komut panoya kopyalandı — kendi ajanına/terminaline yapıştır."); }
      catch { toast("Kopyalanamadı — warden-report/remediation-playbook.md'ye bakabilirsin."); }
    };
    drawerEsc = e => { if (e.key === "Escape") close(); };
    document.addEventListener("keydown", drawerEsc);

    scanAndPollGaps(key, (findings, err) => {
      const body = wrap.querySelector(".sk-gaps-body");
      if (!body) return; // çekmece kapatıldı
      if (err){ body.innerHTML = `<div class="sk-note">⚠ ${esc(err)}</div>`; return; }
      lastFindings = findings;
      body.innerHTML = renderGapsList(findings);
    });
  }
  let drawerEsc = null;
  function closeDrawer(){
    const d = target.querySelector(".sk-drawer"); if (d) d.remove();
    if (drawerEsc){ document.removeEventListener("keydown", drawerEsc); drawerEsc = null; }
  }

  const VBADGE = {
    verified: `<span class="sk-vtag v-ok">✓ DOĞRULANDI</span>`,
    claimed:  `<span class="sk-vtag v-claim">◐ DOĞRULANMADI</span>`,
    failed:   `<span class="sk-vtag v-fail">✗ DÜŞTÜ</span>`,
  };
  function abilityCard(l, isRelic){
    const vs = !isRelic && l.status === "active" ? verState(l, state.verification) : null;
    const pending = !isRelic && l.status !== "active" && state.pendingKeys.has(l.key);
    let btn = "";
    if (!isRelic && !pending){
      if (l.status === "open" || l.status === "partial")
        btn = `<button class="sk-btn sk-act" data-key="${l.key}" data-kind="equip">⚒ Kuşan (+${l.weight})</button>`;
      else if (vs === "claimed")
        btn = `<button class="sk-btn ghost sk-act" data-key="${l.key}" data-kind="verify">🔍 Doğrula</button>`;
      else if (vs === "failed")
        btn = `<button class="sk-btn sk-act" data-key="${l.key}" data-kind="equip">⚒ Onar</button>`;
    }
    return `<div class="sk-card sk-ability ${pending ? "processing" : l.status}${vs === "claimed" ? " ghosted" : ""}${vs === "failed" ? " dropped" : ""}">
      <div class="sk-ic">${l.icon}</div>
      <div class="sk-abody">
        <div class="sk-nm">${esc(l.name)} <span class="sk-tag ${pending ? "t-processing" : "t-" + l.status}">${pending ? "⏳ İŞLENİYOR" : TAG[l.status]}</span>${vs ? VBADGE[vs] : ""}</div>
        <div class="sk-ds">${esc(l.desc)}</div>
        ${vs === "claimed" ? `<div class="sk-note ghost">🔍 Aktif ama kanıtlanmadı — hayalet zırh. Doğrulanınca katılaşır.</div>` : ""}
        ${l.note ? `<div class="sk-note">⚠ ${esc(l.note)}</div>` : ""}
        ${pending ? `<div class="sk-processing-note"><span class="dot"></span>Ajan düzeltmeyi uyguluyor ve test ediyor — bitince zırh kendiliğinden kuşanır.</div>` : ""}
        ${btn}
      </div></div>`;
  }

  function render(){
    const s = computeMeasuredScore(state.layers, state.verification); // ÖLÇÜLEN (birincil)
    const claimed = computeScore(state.layers);                       // İDDİA (ikincil)
    const r = rankOf(s, posture.ranks);
    const nr = nextRank(s, posture.ranks);
    const eq = equippedCount(state.layers);
    const verifiedOn = state.layers.filter(l => l.status === "active" && verState(l, state.verification) === "verified").length;
    const m = state.metrics; const bd = m.breakdown || {};
    const xpPct = nr ? Math.min(100, Math.round((s - r.min) / ((nr.min - r.min) || 1) * 100)) : 100;

    // Alarm listesi: DÜŞEN (acil) → KUŞAN (eksik) → DOĞRULA (hayalet).
    const vsOf = l => verState(l, state.verification);
    const alarms = [
      ...state.layers.filter(l => l.status === "active" && vsOf(l) === "failed").map(l => ({ l, kind:"failed" })),
      ...state.layers.filter(l => l.status === "open" || l.status === "partial").sort((a,b)=>b.weight-a.weight).map(l => ({ l, kind:"equip" })),
      ...state.layers.filter(l => l.status === "active" && vsOf(l) === "claimed").map(l => ({ l, kind:"verify" })),
    ];
    const ALARM = {
      failed:{ tag:"💥 ZIRH DÜŞTÜ", btn:"⚒ Onar", cls:"failed" },
      equip:{ tag:`+güç`, btn:"⚒ Kuşan", cls:"" },
      verify:{ tag:"🔍 doğrulanmadı", btn:"🔍 Doğrula", cls:"ghost-alarm" },
    };

    target.innerHTML = `
    <div class="sk">
      <div class="sk-top">
        <div><div class="sk-title">⚔️ Güvenlik Şövalyesi</div>
          <div class="sk-sub">Bot &amp; kötüye kullanım savunmanın canlı karakteri — güç kazandıkça yükselir.</div></div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          ${loopEnabled ? `<button class="sk-btn sk-rescan">🔄 Yeniden tara & doğrula</button>` : ""}
          <button class="sk-btn ghost sk-reset" style="display:${state.original ? "" : "none"}">↺ Gerçek duruma dön</button>
        </div>
      </div>

      <div class="sk-hero">
        <div class="sk-card sk-stage">
          <div class="sk-flash"></div>
          <div class="sk-rank">⚜ ${esc(r.title)}</div>
          <div class="sk-lvl">★ Lv ${r.lv}</div>
          <div class="sk-warrior">
            <div class="sk-knight-aura" style="--lv:${r.lv}"></div>
            <img class="sk-knight-img" src="${assetBase}/knight-lv${r.lv}.png" alt="Güvenlik Şövalyesi — Lv ${r.lv}" />
            <div class="sk-knight-fallback" hidden>${buildKnightSVG(posture, state.layers, state.verification)}</div>
          </div>
          <div class="sk-power">${s}<span>/100 ölçülen güç</span></div>
          ${claimed !== s ? `<div class="sk-claimed">iddia ${claimed} · <b>ölçülen ${s}</b> — fark ${claimed - s} kanıtsız</div>` : ""}
          <div class="sk-eq">🛡️ ${eq.on}/${eq.total} zırh · ✓ ${verifiedOn} doğrulandı</div>
          <div class="sk-bars">
            <div class="sk-bar"><div class="sk-lab"><span>Güç (HP)</span><span>${s}/100</span></div>
              <div class="sk-track"><div class="sk-fill hp" style="width:${s}%"></div></div></div>
            <div class="sk-bar"><div class="sk-lab"><span>${nr ? "Sonraki: " + esc(nr.title) : "Zirve rütbe"}</span>
              <span>${nr ? (nr.min - s) + " güç" : "MAX"}</span></div>
              <div class="sk-track"><div class="sk-fill xp" style="width:${xpPct}%"></div></div></div>
          </div>
        </div>

        <div class="sk-card sk-alarm">
          <div class="sk-alarm-h"><span class="sk-ping"></span> Zayıf Noktalar — Görev Çağrısı</div>
          ${alarms.length ? alarms.map(({l,kind}) => {
            const pending = kind === "equip" && state.pendingKeys.has(l.key);
            return `
            <div class="sk-quest ${pending ? "" : ALARM[kind].cls}">
              <div class="sk-qi">${l.icon}</div>
              <div class="sk-qt"><b>${esc(l.name)} <span class="sk-qk">${pending ? "⏳ İŞLENİYOR" : ALARM[kind].tag}</span></b><small>${pending ? "Ajan düzeltmeyi uyguluyor — bitince zırh kendiliğinden kuşanır." : esc(l.note || l.desc)}</small></div>
              ${pending ? "" : `<button class="sk-btn sk-act" data-key="${l.key}" data-kind="${kind === "verify" ? "verify" : "equip"}">${ALARM[kind].btn}</button>`}
            </div>`; }).join("")
            : `<div class="sk-quest done"><div class="sk-qi">🏆</div><div class="sk-qt"><b>Tüm zırhlar kuşanıldı ve doğrulandı!</b><small>Şövalyen tam teçhizatlı. Yalnızca izleme kaldı.</small></div></div>`}
        </div>
      </div>

      <div class="sk-sect">🛡️ Kuşanılan Güçler</div>
      ${(() => {
        const groups = {};
        for (const l of state.layers){ const g = l.group || ""; (groups[g] ||= []).push(l); }
        const keys = Object.keys(groups);
        const relicsHtml = state.relics.length
          ? `<div class="sk-group">✨ Kalıntılar</div><div class="sk-grid">${state.relics.map(l => abilityCard(l, true)).join("")}</div>` : "";
        if (keys.length <= 1)
          return `<div class="sk-grid">${state.layers.map(l => abilityCard(l, false)).join("")}</div>${relicsHtml}`;
        return keys.map(g =>
          `${g ? `<div class="sk-group">${g}</div>` : ""}<div class="sk-grid">${groups[g].map(l => abilityCard(l, false)).join("")}</div>`
        ).join("") + relicsHtml;
      })()}

      <div class="sk-sect">📜 Savaş Günlüğü <span class="sk-muted">— son 24 saat</span></div>
      <div class="sk-stats">
        ${[["Püskürtülen saldırı", m["Püskürtülen saldırı"]], ["Korunan istek", m["Korunan istek"]],
           ["Ulaşan elçi", m["Ulaşan elçi (e-posta)"]], ["Aktif tehdit", m["Aktif tehdit"]]]
          .map(([l,v]) => `<div class="sk-card sk-stat"><div class="v">${esc(v ?? "–")}</div><div class="l">${l}</div></div>`).join("")}
        ${(() => { const ff = m["Dostu vurma"]; if (ff === undefined) return "";
          const bad = Number(ff) > 0;
          return `<div class="sk-card sk-stat ff ${bad ? "bad" : "good"}"><div class="v">${esc(ff)}</div><div class="l">🎯 Dostu vurma${bad ? " ⚠" : " ✓"}</div></div>`; })()}
        ${Object.entries(bd).map(([l,v]) => `<div class="sk-card sk-stat sub"><div class="v">${esc(v)}</div><div class="l">↳ ${l}</div></div>`).join("")}
      </div>

      <div class="sk-foot"><b>Ölçülen güç ${s}/100</b> (iddia ${claimed}). Aktif+doğrulanmış zırh tam,
        aktif ama <b>kanıtsız (hayalet)</b> zırh yalnızca 0,6 sayar — panel <i>iddia edileni değil ölçüleni</i> gösterir.
        Doğrulama backend self-check + saldırı-testinden gelir; bir savunma bozulursa zırh düşer ve alarm çalar. Panel yönetim-içidir.</div>
    </div>`;

    // Gerçekçi görsel yüklenemezse SVG şövalyeye düş.
    const kimg = target.querySelector(".sk-knight-img");
    if (kimg) kimg.onerror = () => {
      kimg.hidden = true;
      const fb = target.querySelector(".sk-knight-fallback"); if (fb) fb.hidden = false;
    };
    const rs = target.querySelector(".sk-rescan"); if (rs) rs.onclick = tryLoop;
    target.querySelectorAll(".sk-act").forEach(b => b.onclick = () => openDrawer(b.dataset.key, b.dataset.kind));
    const rb = target.querySelector(".sk-reset");
    if (rb) rb.onclick = () => {
      if (state.original){
        state.layers.forEach((l,i)=>l.status = state.original.st[i]);
        state.verification = state.original.ver;
        state.original = null;
      }
      render(); toast("↺ Gerçek duruma dönüldü.");
    };
  }

  // İlk yükleme: backend varsa oku, sonra çiz (henüz baseline yok → kutlama tetiklenmez).
  render();
  syncAndRender(false);
  // Canlı: periyodik yenileme — ajan kuyruğu arka planda (terminalden ya da /loop ile) işleyip
  // posture'u güncellediğinde, şövalye kendiliğinden zırhlanır VE bunu kutlar (announce=true).
  if (options.pollMs && options.endpoint) setInterval(() => { syncAndRender(true); }, options.pollMs);
  return { refresh: async () => { await syncAndRender(true); },
    getScore: () => computeMeasuredScore(state.layers, state.verification) };
}

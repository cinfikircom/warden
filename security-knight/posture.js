/**
 * GÜVENLİK ŞÖVALYESİ — Zırh Kaydı (tek düzenleme noktası)
 * =========================================================================
 * Her savunma katmanı = bir ZIRH. Yeni zırh eklemek için diziye bir nesne ekle:
 *   { key, icon, name, realName, weight, z, status, desc, note?, svg, weakSvg?, quest? }
 * - status  : "active" | "partial" | "open" | "optional"  (GERÇEK kaynağı backend'dir; bkz. README)
 * - weight  : güce katkısı (Σ ağırlık = 100 önerilir)
 * - z       : şövalye üzerinde çizim sırası (küçük=arkada). BASE_Z = 5.
 * - svg     : zırh AKTİFken karaktere eklenen parça (SVG fragmanı, viewBox 0 0 150 210)
 * - weakSvg : zırh EKSİKken gösterilen zayıflık işareti (ör. kalkandaki çatlak) — opsiyonel
 * - quest   : eksikse "Kuşan" görevinin içeriği (neden / adımlar / kabul)
 * Zırhlar aktifleştikçe şövalye dolar; hepsi aktifse tam teçhizatlı şövalye olur.
 * =========================================================================
 */

export const BASE_Z = 5;

export const POSTURE = {
  // Şövalyenin her zaman görünen çekirdeği (çıplak acemi + temel kılıç).
  base: /*svg*/`
    <g id="knight-base">
      <rect x="60" y="150" width="13" height="46" rx="5" fill="#8a7660"/>
      <rect x="77" y="150" width="13" height="46" rx="5" fill="#8a7660"/>
      <rect x="58" y="192" width="17" height="9" rx="3" fill="#5a4a38"/>
      <rect x="75" y="192" width="17" height="9" rx="3" fill="#5a4a38"/>
      <rect x="42" y="90" width="12" height="48" rx="6" fill="#9c866a"/>
      <rect x="96" y="90" width="12" height="48" rx="6" fill="#9c866a"/>
      <path d="M54 86 Q75 80 96 86 L100 150 Q75 158 50 150 Z" fill="#a98f6e"/>
      <circle cx="75" cy="60" r="16" fill="#e8c9a0"/>
      <path d="M60 56 Q75 40 90 56 L90 50 Q75 38 60 50 Z" fill="#6b4f36"/>
      <!-- temel kılıç (sağ el) -->
      <g id="base-sword"><rect x="112" y="82" width="6" height="56" rx="2" fill="#d7ddE6" stroke="#9aa2b0"/>
        <rect x="105" y="134" width="20" height="5" rx="2" fill="#8a6216"/></g>
    </g>`,

  layers: [
    {
      key:"honeypot", icon:"🕸️", name:"Gölge Pelerini", realName:"Honeypot (ekran-dışı tuzak)",
      status:"active", weight:15, z:1,
      verify:{ selfCheck:"honeypotFieldPresent", attackTest:"honeypot" },
      desc:"Ekran-dışı honeypot; dolduran anında bot. Gelişmiş botları da yakalar.",
      svg:/*svg*/`<path d="M48 84 Q28 142 42 194 L75 174 L108 194 Q122 142 102 84 Z" fill="#3f3a4d" opacity=".9"/>`,
    },
    {
      key:"hmac", icon:"🛡️", name:"Mühürlü Kalkan", realName:"HMAC imzalı zaman damgası",
      status:"active", weight:10, z:9,
      desc:"HMAC imzalı damga. <1,5sn = bot, >1sa = eski. Bot kendi damgasını üretemez.",
      svg:/*svg*/`<g><path d="M18 96 Q40 88 46 96 L46 128 Q33 144 18 128 Z" fill="#c8912f" stroke="#8a6216" stroke-width="2"/>
        <path d="M31 106 l4 6 l-4 6 l-4 -6 z" fill="#fff4d0"/></g>`,
    },
    {
      key:"token1x", icon:"🔗", name:"Kırılmaz Mühür", realName:"Tek-kullanımlık + bağlı damga",
      status:"open", weight:12, z:10, requires:"hmac",
      desc:"Damgayı nonce ile tek-kullanımlık yap + e-posta/IP'ye bağla, süreyi 10–15 dk'ya indir.",
      note:"Zayıf nokta: imzalı ama tek-kullanımlık değil → damga 1 saat boyunca tekrar (replay) kullanılabilir.",
      svg:/*svg*/`<path d="M18 96 Q40 88 46 96 L46 128 Q33 144 18 128 Z" fill="none" stroke="#ffe08a" stroke-width="3"/>`,
      weakSvg:/*svg*/`<path d="M31 96 L27 112 L37 118 L30 128" stroke="#c23b46" stroke-width="1.8" fill="none"/>`,
      quest:{
        why:"İmza sahteciliği engelliyor ama aynı geçerli damga 1 saatlik pencerede yeniden kullanılabilir (replay).",
        steps:[
          "Damganın payload'una rastgele bir nonce ekle.",
          "Nonce'u sunucuda (Redis/DB) TTL ile sakla; ilk kullanımda 'kullanıldı' işaretle.",
          "İmzaya e-posta + IP'yi de dahil et (transfer edilemesin).",
          "Üst geçerlilik süresini 1 saatten 10–15 dk'ya indir.",
        ],
        acceptance:["Aynı damgayla ikinci gönderim reddedilir","Damga başka e-posta/IP ile çalışmaz"],
      },
    },
    {
      key:"rlip", icon:"🧱", name:"Sur Duvarı", realName:"Rate-limit — IP başına",
      status:"active", weight:8, z:6,
      desc:"IP başına saatte 5 kod isteği.",
      svg:/*svg*/`<path d="M55 86 Q75 80 95 86 L98 128 Q75 136 52 128 Z" fill="#8b93a1" stroke="#5f6674" stroke-width="2"/>
        <path d="M75 84 L75 132" stroke="#c8912f" stroke-width="2"/>`,
    },
    {
      key:"rlmail", icon:"⛓️", name:"Bekçi Zinciri", realName:"Rate-limit — e-posta başına",
      status:"active", weight:8, z:7,
      desc:"E-posta başına saatte 5 istek; dağıtık kurban-bombalamayı sınırlar.",
      svg:/*svg*/`<ellipse cx="50" cy="92" rx="12" ry="9" fill="#79818f" stroke="#5f6674"/>
        <ellipse cx="100" cy="92" rx="12" ry="9" fill="#79818f" stroke="#5f6674"/>`,
    },
    {
      key:"rlverify", icon:"🔒", name:"Kilit Muhafızı", realName:"Rate-limit — kod deneme",
      status:"active", weight:8, z:7,
      desc:"Kod deneme: e-posta başına 10 dk'da 8 deneme; brute-force'u kırar.",
      svg:/*svg*/`<rect x="41" y="116" width="14" height="22" rx="5" fill="#79818f" stroke="#5f6674"/>
        <rect x="95" y="116" width="14" height="22" rx="5" fill="#79818f" stroke="#5f6674"/>`,
    },
    {
      key:"silent", icon:"🥷", name:"Hayalet Başlığı", realName:"Sessiz bot yanıtı (içerik paritesi)",
      status:"active", weight:12, z:8,
      verify:{ selfCheck:null, attackTest:"honeypot", needsTestHook:true },
      desc:"Bot da insanla aynı yanıtı görür, e-posta gitmez. Yakalandığını anlayamaz.",
      svg:/*svg*/`<path d="M58 60 Q75 34 92 60 Q92 74 84 78 L66 78 Q58 74 58 60 Z" fill="#2f3140" opacity=".85"/>`,
    },
    {
      key:"consttime", icon:"⏳", name:"Zaman Peçesi", realName:"Sabit-süreli yanıt (async e-posta)",
      status:"open", weight:12, z:6,
      desc:"E-postayı senkron gönderme, kuyruğa at — bot/insan yanıt süresi eşitlensin.",
      note:"Zayıf nokta: bot yolu daha hızlı dönüp süre ölçerek yakalanmayı sezebilir (zamanlama sızıntısı).",
      svg:/*svg*/`<g><rect x="59" y="150" width="15" height="30" rx="4" fill="#9aa2b0" stroke="#5f6674"/>
        <rect x="76" y="150" width="15" height="30" rx="4" fill="#9aa2b0" stroke="#5f6674"/></g>`,
      quest:{
        why:"Bot yolu e-posta göndermediği için daha hızlı dönebilir; saldırgan süreyi ölçerek yakalandığını anlar (zamanlama oracle'ı).",
        steps:[
          "E-posta gönderimini senkron çağırma; bir kuyruğa (queue/job) at.",
          "Hem bot hem insan yolu aynı anda 'e-postanızı kontrol edin' döndürsün.",
          "Gerekirse sabit bir minimum yanıt süresi uygula.",
        ],
        acceptance:["Bot ve insan yanıt süreleri istatistiksel olarak ayırt edilemez","UX daha hızlı (SMTP beklenmiyor)"],
      },
    },
    {
      key:"observ", icon:"👁️", name:"Kâhin Miğferi", realName:"Gözlemlenebilirlik + alarm",
      status:"open", weight:8, z:8,
      desc:"Bot yakalama olaylarını say/logla, ani artışta alarm ver.",
      note:"Zayıf nokta: saldırıyı göremezsin → gerekince ek savunmayı devreye alamazsın.",
      svg:/*svg*/`<g><path d="M59 58 Q75 36 91 58 L91 52 Q75 34 59 52 Z" fill="#9aa2b0" stroke="#5f6674"/>
        <rect x="66" y="56" width="18" height="5" rx="2" fill="#3a3f47"/>
        <circle cx="75" cy="47" r="3" fill="#41d1e0"/></g>`,
      quest:{
        why:"Saldırıya sessiz kalman doğru; ama sen görebilmelisin ki gerekince fallback'i (Turnstile vb.) devreye alasın.",
        steps:[
          "Her bot-yakalama olayını sebebiyle (honeypot/hız/replay/rate-limit) say.",
          "Bir metrik uç noktası yayınla: GET /api/security/metrics.",
          "Ani artışta (ör. 5dk'da >N) alarm/webhook tetikle.",
        ],
        acceptance:["Panelde canlı metrik akıyor","Ani saldırıda alarm düşüyor"],
      },
    },
    {
      key:"enum", icon:"🎭", name:"İki Yüz Maskesi", realName:"E-posta enumerasyon paritesi",
      status:"partial", weight:7, z:9,
      desc:"Kayıtlı/kayıtsız e-posta aynı yanıtı VE süreyi almalı.",
      note:"Doğrula: bot/insan paritesi var; kayıtlı/kayıtsız paritesini de teyit et.",
      svg:/*svg*/`<rect x="64" y="60" width="22" height="9" rx="4" fill="#5f6674" opacity=".9"/>`,
      quest:{
        why:"Kayıtlı vs kayıtsız e-posta farklı yanıt/süre alırsa hangi e-postaların kayıtlı olduğu sızar.",
        steps:["Her iki durumda da aynı gövdeyi döndür","Yanıt sürelerini eşitle (async gönderim buna da yardım eder)"],
        acceptance:["Kayıtlı/kayıtsız yanıt ve süre ayırt edilemez"],
      },
    },
  ],

  // Efsanevi kalıntılar (opsiyonel sertleştirme; skoru düşürmez, ekstra parlaklık).
  relics: [
    { key:"globalcap", icon:"📯", name:"Kuşatma Borusu", status:"optional", weight:0, z:11,
      desc:"Global gönderim tavanı + anomali — dağıtık taşkına karşı sağlayıcı itibarını korur.",
      svg:/*svg*/`<path d="M75 26 l7 -12 l-14 0 z" fill="#f4c65a" stroke="#b9861f"/>` },
    { key:"challenge", icon:"🌩️", name:"Sınav Kapısı", status:"optional", weight:0, z:11,
      desc:"Turnstile / PoW — önleyici değil, yalnızca alarm tetikte devreye giren fallback.", svg:"" },
    { key:"fairscale", icon:"⚖️", name:"Adil Terazi", status:"optional", weight:0, z:11,
      desc:"Bot istekleri kurbanın kotasını tüketmesin — limiti yalnızca gerçek gönderime say.", svg:"" },
    { key:"a11y", icon:"♿", name:"Erişim Tılsımı", status:"optional", weight:0, z:11,
      desc:"Honeypot'a tabindex=-1 · aria-hidden · autocomplete=off — false-positive önler.", svg:"" },
  ],

  ranks: [
    { min:0,  lv:1, title:"Acemi Nöbetçi" },
    { min:21, lv:2, title:"Çırak Muhafız" },
    { min:41, lv:3, title:"Kalkan Eri" },
    { min:61, lv:4, title:"Muhafız Şövalyesi" },
    { min:81, lv:5, title:"Kale Kumandanı" },
    { min:96, lv:6, title:"Efsane Muhafız" },
  ],

  // Canlı metrikler — gerçek projede /api/security/metrics'ten gelir (README).
  metrics: {
    "Püskürtülen saldırı":348, "Korunan istek":1240, "Ulaşan elçi (e-posta)":892, "Aktif tehdit":"Yok",
    breakdown:{ "Tuzağa düşen":210, "Çok hızlı (<1,5sn)":96, "Replay / eski damga":25, "Rate-limit reddi":17 },
  },
};

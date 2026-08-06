// FP muhafızı — bu dosya HİÇ bulgu üretmemeli.
const ALLOWED = "https://app.example.com";

export function clear(el) {
  // Boş temizleme meşru kullanım → FE-3 tetiklenmemeli.
  el.innerHTML = "";
}

export function setName(el, userName) {
  // textContent güvenli → FE-3 tetiklenmemeli.
  el.textContent = userName;
}

export function send(frame, payload) {
  // Kesin köken verilmiş → FE-5 tetiklenmemeli.
  frame.postMessage(payload, ALLOWED);
}

// Origin doğrulaması var → FE-5 tetiklenmemeli.
window.addEventListener("message", (e) => {
  if (e.origin !== ALLOWED) return;
  handle(e.data);
});

// Bilerek açıklı fixture — yalnızca test amaçlı. Üretimde KULLANMA.

// FE-3: innerHTML ve document.write ile dinamik HTML yazımı.
export function render(name) {
  const el = document.getElementById("out");
  el.innerHTML = "<b>" + name + "</b>";
  document.write(location.search);
}

// FE-5: postMessage wildcard origin.
export function send(frame, data) {
  frame.contentWindow.postMessage(data, "*");
}

// FE-5: message dinleyicisinde gönderici origin doğrulaması yok.
window.addEventListener("message", (e) => {
  handleCommand(e.data);
});

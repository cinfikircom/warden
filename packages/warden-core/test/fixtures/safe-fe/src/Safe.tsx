// FP muhafızı — bu dosya HİÇ bulgu üretmemeli.
import React from "react";
import DOMPurify from "dompurify";

export function setTheme(): void {
  // Token değil, tercih: FE-1 tetiklenmemeli.
  sessionStorage.setItem("theme", "dark");
}

export function Safe({ html, id }: { html: string; id: string }): React.ReactElement {
  return (
    <div>
      {/* Sanitize edilmiş → FE-3 tetiklenmemeli. */}
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />
      {/* rel=noopener var → FE-6 tetiklenmemeli. */}
      <a href="/docs" target="_blank" rel="noopener noreferrer">
        Dokümanlar
      </a>
      {/* String literal ile başlıyor → FE-3 (unsafe-url-binding) tetiklenmemeli. */}
      <a href={"/user/" + id}>Profil</a>
    </div>
  );
}

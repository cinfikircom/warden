// Bilerek açıklı fixture — yalnızca test amaçlı. Üretimde KULLANMA.
import React from "react";

interface User {
  readonly bio: string;
  readonly website: string;
}

// FE-1: token web storage'da.
export function login(token: string): void {
  localStorage.setItem("access_token", token);
}

export function Profile({ user }: { user: User }): React.ReactElement {
  return (
    <div>
      {/* FE-3: sanitize edilmemiş HTML React ağacına basılıyor. */}
      <div dangerouslySetInnerHTML={{ __html: user.bio }} />
      {/* FE-6: target=_blank var, rel=noopener yok. */}
      <a href="/terms" target="_blank">
        Şartlar
      </a>
      {/* FE-3 (low): doğrulanmamış dinamik URL binding. */}
      <a href={user.website}>Site</a>
    </div>
  );
}

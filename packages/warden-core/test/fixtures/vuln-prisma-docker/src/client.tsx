// KASITLI açıklı frontend kodu (test fixture'ı).
import React from "react";

export function saveToken(token: string): void {
  localStorage.setItem("access_token", token);
}

export function Comment({ html }: { html: string }): React.ReactElement {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

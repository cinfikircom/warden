// Client-side payment bootstrap — served to the browser.
// WRONG: a payment provider SECRET key hardcoded in a client bundle (catastrophic).
// (Placeholder value on purpose — real secret keys must never live in client code.)
const STRIPE_SECRET_KEY = "PLACEHOLDER_never_put_a_real_secret_here";

export function startCheckout(cart) {
  return fetch("/api/checkout", { method: "POST", body: JSON.stringify(cart) });
}

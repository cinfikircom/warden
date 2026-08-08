// camelCase anahtar adları — JS/TS'te standart, ama kelime-sınırlı desen bunları kaçırıyordu.
export const config = {
  cookieSecret: "session_cookie_secret_key_here",
  cryptoKey: "a_secure_key_for_crypto_here",
  zapApiKey: "v9dn0balpqas1pcc281tn5ood1",
  dbPassword: "Sup3rSecretPassw0rd!",
  // Bunlar secret DEĞİL: değer boşluk içeriyor ya da env'den geliyor.
  secretDescription: "bu alan bir açıklama metnidir",
  apiKeyFromEnv: process.env.API_KEY,
};

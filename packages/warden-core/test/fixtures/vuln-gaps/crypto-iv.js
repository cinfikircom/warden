// Bilerek açıklı fixture — yalnızca test amaçlı. Üretimde KULLANMA.
const crypto = require("node:crypto");

// B3-static-iv-const: modül düzeyinde sabit IV.
const IV = Buffer.from("0102030405060708");

// B3-static-iv: çağrıda sıfır IV.
function encrypt(key, plaintext) {
  const cipher = crypto.createCipheriv("aes-256-cbc", key, Buffer.from("0000000000000000"));
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

module.exports = { encrypt, IV };

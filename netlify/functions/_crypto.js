// netlify/functions/_crypto.js
// AES-256-GCM helpers for encrypting OAuth tokens before storing them in
// Netlify Blobs. Required env var: TOKEN_ENCRYPTION_KEY — a 64-character
// hex string (32 random bytes). Generate one with:
//   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
// Treat it like a master password: if it leaks, every stored token is
// exposed; if you lose it, every stored token becomes unreadable.

const crypto = require("crypto");

function getKey() {
  const hex = process.env.TOKEN_ENCRYPTION_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error("TOKEN_ENCRYPTION_KEY must be set to a 64-character hex string (32 bytes).");
  }
  return Buffer.from(hex, "hex");
}

function encrypt(plaintext) {
  const key = getKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Store iv + authTag + ciphertext together, base64-encoded.
  return Buffer.concat([iv, authTag, ciphertext]).toString("base64");
}

function decrypt(encoded) {
  const key = getKey();
  const buf = Buffer.from(encoded, "base64");
  const iv = buf.subarray(0, 12);
  const authTag = buf.subarray(12, 28);
  const ciphertext = buf.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString("utf8");
}

module.exports = { encrypt, decrypt };

// netlify/functions/_auth.js
// Shared authentication helpers: password hashing (scrypt) and signed,
// httpOnly session cookies (HMAC-SHA256), with no external dependencies.
//
// Required env vars:
// - SESSION_SECRET: a long random string used to sign session cookies.
//   If this leaks, anyone can forge a valid session — treat it like a
//   password. Generate one with, e.g., a password manager (32+ chars).

const crypto = require("crypto");

const SESSION_COOKIE = "dash_session";
const SESSION_TTL_SECONDS = 60 * 60 * 8; // 8 hours

// ---- Password hashing ----

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  const a = Buffer.from(hash, "hex");
  const b = Buffer.from(expectedHash, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ---- Session cookies ----

function base64url(input) {
  return Buffer.from(input).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(input) {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((input.length + 3) % 4);
  return Buffer.from(padded, "base64").toString("utf8");
}

function sign(payload) {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error("SESSION_SECRET environment variable is not set.");
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

function createSessionCookie(user) {
  const payload = JSON.stringify({
    u: user.username,
    r: user.role || "member",
    exp: Date.now() + SESSION_TTL_SECONDS * 1000,
  });
  const encoded = base64url(payload);
  const signature = sign(encoded);
  const token = `${encoded}.${signature}`;
  return `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}; Path=/`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/`;
}

function getCookie(event, name) {
  const header = (event.headers && (event.headers.cookie || event.headers.Cookie)) || "";
  const match = header.split(";").map((c) => c.trim()).find((c) => c.startsWith(name + "="));
  return match ? match.slice(name.length + 1) : null;
}

/**
 * Returns the authenticated user ({ username, role }) from the request's
 * session cookie, or null if missing/invalid/expired.
 */
function getSessionUser(event) {
  try {
    const token = getCookie(event, SESSION_COOKIE);
    if (!token) return null;

    const [encoded, signature] = token.split(".");
    if (!encoded || !signature) return null;

    const expectedSignature = sign(encoded);
    const a = Buffer.from(signature, "hex");
    const b = Buffer.from(expectedSignature, "hex");
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

    const payload = JSON.parse(base64urlDecode(encoded));
    if (!payload.exp || Date.now() > payload.exp) return null;

    return { username: payload.u, role: payload.r };
  } catch (err) {
    return null;
  }
}

module.exports = {
  hashPassword,
  verifyPassword,
  createSessionCookie,
  clearSessionCookie,
  getSessionUser,
  SESSION_COOKIE,
};

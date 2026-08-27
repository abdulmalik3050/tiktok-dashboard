// netlify/functions/tiktok-login.js
// Starts the TikTok OAuth flow server-side, so the Client Key never has to be
// hardcoded in client-side HTML/JS. Set TIKTOK_CLIENT_KEY in Netlify's
// environment variables (Site configuration > Environment variables).
//
// Security hardening:
// - A cryptographically random `state` value is generated and stored in an
//   httpOnly cookie, then verified in tiktok-callback.js to prevent CSRF
//   (an attacker tricking a user into linking the attacker's TikTok account
//   to the victim's session).
// - Basic IP rate limiting to slow down automated abuse of this endpoint.

const crypto = require("crypto");
const { checkRateLimit, getClientIp } = require("./_rate-limit");

exports.handler = async function (event) {
  const ip = getClientIp(event);
  const rate = await checkRateLimit(`login:${ip}`, 20, 600); // 20 requests / 10 min per IP
  if (!rate.allowed) {
    return {
      statusCode: 429,
      headers: { "Content-Type": "text/html; charset=utf-8" },
      body: "<h2>محاولات كثيرة جدًا</h2><p>الرجاء الانتظار قليلاً قبل المحاولة مرة أخرى.</p>",
    };
  }

  const CLIENT_KEY = process.env.TIKTOK_CLIENT_KEY;
  const REDIRECT_URI = "https://velvety-stardust-80781c.netlify.app/.netlify/functions/tiktok-callback";
  const SCOPES = "user.info.basic,user.info.stats,video.list";

  if (!CLIENT_KEY) {
    return {
      statusCode: 500,
      headers: { "Content-Type": "text/html; charset=utf-8" },
      body: "<h2>Server misconfiguration</h2><p>TIKTOK_CLIENT_KEY environment variable is not set on Netlify.</p>",
    };
  }

  // Cryptographically strong, unguessable state value (32 random bytes).
  const state = crypto.randomBytes(32).toString("hex");

  const url =
    "https://www.tiktok.com/v2/auth/authorize/" +
    "?client_key=" + encodeURIComponent(CLIENT_KEY) +
    "&scope=" + encodeURIComponent(SCOPES) +
    "&response_type=code" +
    "&redirect_uri=" + encodeURIComponent(REDIRECT_URI) +
    "&state=" + state;

  return {
    statusCode: 302,
    headers: {
      Location: url,
      // httpOnly: JS on the page can't read/tamper with it.
      // Secure: only sent over HTTPS. SameSite=Lax: sent on the top-level
      // redirect back from TikTok, but not on cross-site form posts/XHR.
      // Max-Age=600: the login flow must complete within 10 minutes.
      "Set-Cookie": `tt_oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/`,
    },
    body: "",
  };
};

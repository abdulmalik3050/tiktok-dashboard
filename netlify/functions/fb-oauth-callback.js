// netlify/functions/fb-oauth-callback.js
// Completes the "Facebook Login for Business" OAuth flow started by
// test-login.html → oauth-callback.html: exchanges the authorization
// `code` shown on oauth-callback.html for a Page Access Token — the
// token business_discovery queries against Instagram actually need
// (see the earlier instagram-lookup.js investigation: Business Discovery
// isn't available through the plain "Instagram Login" token/host, only
// through a Facebook Page's linked Instagram Business Account).
//
// Flow (all server-side, triggered by one GET call with a fresh `code`):
//   1. code -> short-lived User Access Token
//      (graph.facebook.com/oauth/access_token)
//   2. short-lived -> long-lived User Access Token
//      (grant_type=fb_exchange_token, ~60 days)
//   3. long-lived User Access Token -> list of Pages + each Page's own
//      Access Token (GET /me/accounts) — a Page token derived from a
//      long-lived user token effectively doesn't expire on its own,
//      as long as the user token behind it stays valid.
//   4. Each Page Access Token is encrypted and stored in Netlify Blobs
//      (never written to a file, never committed to the repo) for later
//      reuse by business_discovery calls.
//
// Required env vars (set in Netlify, never hardcoded here):
// - FB_APP_SECRET: the Meta App's secret.
// - TOKEN_ENCRYPTION_KEY: same 32-byte hex key already used elsewhere in
//   this project to encrypt tokens at rest (see _crypto.js).
//
// Usage: after clicking through test-login.html and landing on
// oauth-callback.html, copy the "code" value shown there (dev box), then
// open, in the SAME browser you're logged into the dashboard with:
//   /.netlify/functions/fb-oauth-callback?code=<that code>
// The JSON response (visible only to you, since it requires a logged-in
// session) lists each linked Page and its Access Token.

const { getSessionUser } = require("./_auth");
const { checkRateLimit, getClientIp } = require("./_rate-limit");
const { getSettingsStore } = require("./_blobs-store");
const { encrypt } = require("./_crypto");

const FB_HOST = "https://graph.facebook.com";
const FB_VERSION = "v21.0";
// نفس الـ client_id العام المستخدم أصلًا بـ test-login.html — معرّف
// تطبيق عام، مو سر، فما يحتاج يكون متغير بيئة.
const APP_ID = "1081947674378336";
const REDIRECT_URI = "https://velvety-stardust-80781c.netlify.app/oauth-callback.html";
const PAGE_TOKENS_BLOB_KEY = "facebook-page-tokens";

async function fbFetch(step, path, params) {
  const url = new URL(`${FB_HOST}/${FB_VERSION}/${path}`);
  Object.entries(params || {}).forEach(([key, value]) => url.searchParams.set(key, value));

  const res = await fetch(url.toString());
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const raw = JSON.stringify(data);
    console.error(`fb-oauth-callback: [${step}] Meta API error — status=${res.status} raw=${raw}`);
    const err = new Error(`فشل بخطوة "${step}" (HTTP ${res.status}) — استجابة Meta الكاملة: ${raw}`);
    err.status = res.status >= 400 && res.status < 500 ? 400 : 502;
    throw err;
  }
  return data;
}

exports.handler = async function (event) {
  const jsonHeaders = { "Content-Type": "application/json", "Cache-Control": "no-store" };

  const user = getSessionUser(event);
  if (!user) {
    return { statusCode: 401, headers: jsonHeaders, body: JSON.stringify({ error: "Not authenticated" }) };
  }

  const ip = getClientIp(event);
  const rate = await checkRateLimit(`fb-oauth-callback:${ip}`, 10, 600);
  if (!rate.allowed) {
    return { statusCode: 429, headers: jsonHeaders, body: JSON.stringify({ error: "طلبات كثيرة، حاول بعد شوي." }) };
  }

  const appSecret = process.env.FB_APP_SECRET;
  if (!appSecret) {
    return {
      statusCode: 500,
      headers: jsonHeaders,
      body: JSON.stringify({ error: "متغير FB_APP_SECRET غير مُعد بإعدادات الخادم." }),
    };
  }

  const code = (event.queryStringParameters && event.queryStringParameters.code) || "";
  if (!code) {
    return {
      statusCode: 400,
      headers: jsonHeaders,
      body: JSON.stringify({ error: "أرفق ?code=... بنهاية الرابط (نفس الكود الظاهر بصفحة oauth-callback.html)." }),
    };
  }

  try {
    // 1) code -> short-lived user token
    const shortLived = await fbFetch("تبديل الكود لتوكن قصير", "oauth/access_token", {
      client_id: APP_ID,
      redirect_uri: REDIRECT_URI,
      client_secret: appSecret,
      code,
    });

    // 2) short-lived -> long-lived user token
    const longLived = await fbFetch("تبديل التوكن لـ long-lived", "oauth/access_token", {
      grant_type: "fb_exchange_token",
      client_id: APP_ID,
      client_secret: appSecret,
      fb_exchange_token: shortLived.access_token,
    });

    // 3) صفحات المستخدم + توكن كل صفحة
    const accounts = await fbFetch("جلب صفحات المستخدم (/me/accounts)", "me/accounts", {
      access_token: longLived.access_token,
    });

    const pages = accounts.data || [];
    if (!pages.length) {
      return {
        statusCode: 404,
        headers: jsonHeaders,
        body: JSON.stringify({ error: "ما فيه أي صفحة فيسبوك مرتبطة بهذا الحساب." }),
      };
    }

    // 4) تخزين توكن كل صفحة مشفّرًا بـ Netlify Blobs — ما يُكتب بأي ملف
    // بالمستودع إطلاقًا، فقط بمخزن Blobs السحابي (نفس آلية تخزين توكن
    // إنستقرام طويل الأمد بـ instagram-lookup.js).
    const store = getSettingsStore();
    const stored = (await store.get(PAGE_TOKENS_BLOB_KEY, { type: "json" }).catch(() => null)) || {};
    for (const page of pages) {
      stored[page.id] = {
        name: page.name,
        token_enc: encrypt(page.access_token),
        updated_at: Date.now(),
      };
    }
    await store.setJSON(PAGE_TOKENS_BLOB_KEY, stored);

    // النتيجة النهائية ترجع بالاستجابة فقط — لصاحب الحساب المسجّل دخوله
    // بنفس الجلسة (الـ endpoint محمي بـ getSessionUser أعلاه)، وما تُطبع
    // ولا تُخزَّن بأي مكان ثاني.
    return {
      statusCode: 200,
      headers: jsonHeaders,
      body: JSON.stringify({
        message: "تم تبديل الكود وتخزين توكن الصفحة (الصفحات) بنجاح بـ Netlify Blobs.",
        pages: pages.map((p) => ({ id: p.id, name: p.name, access_token: p.access_token })),
      }),
    };
  } catch (err) {
    console.error("fb-oauth-callback: failed:", err);
    return {
      statusCode: err.status || 502,
      headers: jsonHeaders,
      body: JSON.stringify({ error: err.message || "تعذر إكمال تبديل التوكن." }),
    };
  }
};

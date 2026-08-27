// netlify/functions/tiktok-callback.js
// Handles the redirect from TikTok after the user authorizes the app.
// Exchanges the authorization code for an access token, fetches the
// user's stats and video list, SAVES the account to persistent storage
// (Netlify Blobs) so multiple accounts can be tracked, then renders a
// results page for this specific account.
//
// Security hardening:
// - Verifies the `state` param against the httpOnly cookie set by
//   tiktok-login.js, rejecting the request if it's missing or doesn't
//   match (CSRF protection).
// - Basic IP rate limiting.

const { getAccountsStore } = require("./_blobs-store");
const { checkRateLimit, getClientIp } = require("./_rate-limit");
const { getSessionUser } = require("./_auth");
const { encrypt } = require("./_crypto");

function getCookie(event, name) {
  const header = (event.headers && (event.headers.cookie || event.headers.Cookie)) || "";
  const match = header.split(";").map((c) => c.trim()).find((c) => c.startsWith(name + "="));
  return match ? match.slice(name.length + 1) : null;
}

exports.handler = async function (event) {
  // Only logged-in company users can link a TikTok account.
  const currentUser = getSessionUser(event);
  if (!currentUser) {
    return htmlResponse(
      `<h2>الرجاء تسجيل الدخول أولاً</h2><p><a href="/login.html">تسجيل الدخول ←</a></p>`
    );
  }

  const ip = getClientIp(event);
  const rate = await checkRateLimit(`callback:${ip}`, 20, 600); // 20 requests / 10 min per IP
  if (!rate.allowed) {
    return htmlResponse(`<h2>محاولات كثيرة جدًا</h2><p>الرجاء الانتظار قليلاً قبل المحاولة مرة أخرى.</p>`);
  }

  const CLIENT_KEY = process.env.TIKTOK_CLIENT_KEY; // set in Netlify env vars, no hardcoded fallback
  const CLIENT_SECRET = process.env.TIKTOK_CLIENT_SECRET_V2; // set in Netlify env vars, never in code
  const REDIRECT_URI = process.env.TIKTOK_REDIRECT_URI || "https://velvety-stardust-80781c.netlify.app/.netlify/functions/tiktok-callback";

  const code = event.queryStringParameters && event.queryStringParameters.code;
  const returnedState = event.queryStringParameters && event.queryStringParameters.state;
  const errorParam = event.queryStringParameters && event.queryStringParameters.error;

  if (errorParam) {
    return htmlResponse(`<h2>TikTok authorization was cancelled or failed.</h2><p>${errorParam}</p>`);
  }

  if (!code) {
    return htmlResponse(`<h2>Missing authorization code.</h2>`);
  }

  // CSRF protection: the state returned by TikTok must match the one we
  // issued and stored in an httpOnly cookie when the login flow started.
  const expectedState = getCookie(event, "tt_oauth_state");
  if (!expectedState || !returnedState || expectedState !== returnedState) {
    return htmlResponse(
      `<h2>تعذّر التحقق من الطلب</h2><p>انتهت صلاحية جلسة تسجيل الدخول أو أن الطلب غير موثوق. الرجاء المحاولة مرة أخرى من صفحة تسجيل الدخول.</p>`
    );
  }

  if (!CLIENT_KEY) {
    return htmlResponse(`<h2>Server misconfiguration</h2><p>TIKTOK_CLIENT_KEY environment variable is not set on Netlify.</p>`);
  }

  if (!CLIENT_SECRET) {
    return htmlResponse(`<h2>Server misconfiguration</h2><p>TIKTOK_CLIENT_SECRET environment variable is not set on Netlify.</p>`);
  }

  try {
    // Step 1: Exchange authorization code for an access token
    const tokenRes = await fetch("https://open.tiktokapis.com/v2/oauth/token/", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cache-Control": "no-cache",
      },
      body: new URLSearchParams({
        client_key: CLIENT_KEY,
        client_secret: CLIENT_SECRET,
        code: code,
        grant_type: "authorization_code",
        redirect_uri: REDIRECT_URI,
      }),
    });

    const tokenData = await tokenRes.json();

    if (!tokenData.access_token) {
      return htmlResponse(`<h2>Failed to get access token</h2><pre>${escapeHtml(JSON.stringify(tokenData, null, 2))}</pre>`);
    }

    const accessToken = tokenData.access_token;
    const refreshToken = tokenData.refresh_token;
    const openId = tokenData.open_id;

    // Step 2: Fetch user info + stats
    const userRes = await fetch(
      "https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name,avatar_url,follower_count,following_count,likes_count,video_count",
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      }
    );
    const userData = await userRes.json();

    // Step 3: Fetch video list with view counts and engagement
    const videoRes = await fetch(
      "https://open.tiktokapis.com/v2/video/list/?fields=id,title,create_time,cover_image_url,share_url,view_count,like_count,comment_count,share_count",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ max_count: 20 }),
      }
    );
    const videoData = await videoRes.json();

    const user = (userData.data && userData.data.user) || {};
    const videos = (videoData.data && videoData.data.videos) || [];
    const hasVideos = videos.length > 0;

    // Save/update this account in persistent storage so the multi-account
    // dashboard (accounts.html) can list it alongside other connected accounts.
    // The refresh token is stored ENCRYPTED (never in plaintext) so the
    // scheduled sync function (sync-tiktok.js) can periodically refresh
    // stats and detect deleted videos without asking the user to log in
    // again. Requires TOKEN_ENCRYPTION_KEY to be set — if it isn't, we
    // still save the account but skip auto-sync for it.
    const accountRecord = {
      platform: "tiktok",
      open_id: openId,
      display_name: user.display_name || openId || "unknown",
      avatar_url: user.avatar_url || "",
      follower_count: user.follower_count || 0,
      following_count: user.following_count || 0,
      likes_count: user.likes_count || 0,
      video_count: user.video_count || 0,
      videos: videos.slice(0, 20).map((v) => ({
        id: v.id || "",
        title: v.title || "",
        view_count: v.view_count || 0,
        like_count: v.like_count || 0,
        comment_count: v.comment_count || 0,
        share_count: v.share_count || 0,
      })),
      connected_at: new Date().toISOString(),
      connected_by: currentUser.username,
      last_synced_at: new Date().toISOString(),
      sync_status: "ok",
    };

    if (refreshToken) {
      try {
        accountRecord.refresh_token_enc = encrypt(refreshToken);
      } catch (encErr) {
        console.error("Could not encrypt refresh token (TOKEN_ENCRYPTION_KEY missing?):", encErr);
      }
    }

    let storageError = null;
    try {
      const store = getAccountsStore();
      await store.setJSON(openId, accountRecord);
    } catch (storageErr) {
      // Don't fail the whole flow if storage has an issue — still show this
      // account's results. Surface the error in the page (temporary, for
      // debugging) so we can see exactly what went wrong.
      console.error("Failed to save account to Blobs:", storageErr);
      storageError = String((storageErr && storageErr.message) || storageErr);
    }

    // Redirect straight to the accounts list (a lightweight success page).
    // The full charts/details view now lives in dashboard.html, which reads
    // the same stored data via list-accounts.js.
    return {
      statusCode: 302,
      headers: {
        Location: storageError ? "/accounts.html?error=" + encodeURIComponent(storageError) : "/accounts.html?connected=" + encodeURIComponent(openId),
        // One-time use: clear the state cookie now that it's been verified.
        "Set-Cookie": "tt_oauth_state=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/",
      },
      body: "",
    };
  } catch (err) {
    return htmlResponse(`<h2>Unexpected error</h2><pre>${escapeHtml(String(err))}</pre>`);
  }
};

function htmlResponse(bodyHtml, extraHeaders) {
  return {
    statusCode: 200,
    headers: Object.assign({ "Content-Type": "text/html; charset=utf-8" }, extraHeaders || {}),
    body: `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>لوحة تحكم TikTok</title>
<style>
  :root {
    --bg-main: #F4F6FB; --bg-card: #FFFFFF; --accent: #3D5A80; --text: #1E293B;
    --text-muted: #64748B; --border: #E2E8F0;
    --card-shadow: 0 1px 3px rgba(0,0,0,0.04), 0 4px 14px rgba(0,0,0,0.06);
  }
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background: var(--bg-main); color: var(--text); margin: 0; direction: rtl; }
  .wrap { max-width: 900px; margin: 0 auto; padding: 36px 20px; }
  .status { display: flex; align-items: center; gap: 14px; margin-bottom: 24px; }
  .check { background: #10B981; color: #fff; width: 34px; height: 34px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; flex-shrink: 0; }
  h1 { font-size: 1.3rem; margin: 0 0 2px; }
  h2 { font-size: 1.05rem; margin: 0 0 14px; }
  .muted { color: var(--text-muted); font-size: 0.9rem; margin: 0; }
  .kpis { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
  .kpi { background: var(--bg-card); border-radius: 14px; box-shadow: var(--card-shadow); padding: 18px 24px; flex: 1; min-width: 140px; text-align: center; }
  .kpi-value { display: block; font-size: 1.5rem; font-weight: 700; color: var(--accent); }
  .kpi-label { font-size: 0.85rem; color: var(--text-muted); }
  .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
  @media (max-width: 700px) { .charts { grid-template-columns: 1fr; } }
  .chart-head { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 4px; }
  .chart-head h2 { margin-bottom: 0; }
  .legend-row { display: flex; gap: 14px; }
  .legend-item { display: flex; align-items: center; gap: 6px; font-size: 0.8rem; color: var(--text-muted); }
  .legend-item i { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
  .donut-layout { display: flex; align-items: center; gap: 18px; }
  .donut-layout canvas { max-width: 150px; max-height: 150px; flex-shrink: 0; }
  .donut-legend { list-style: none; margin: 0; padding: 0; flex: 1; display: flex; flex-direction: column; gap: 10px; }
  .donut-legend li { display: flex; align-items: center; gap: 8px; font-size: 0.85rem; }
  .donut-legend .dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .donut-legend .legend-label { color: var(--text); flex: 1; }
  .donut-legend .legend-pct { color: var(--text-muted); font-weight: 600; }
  .card { background: var(--bg-card); border-radius: 14px; box-shadow: var(--card-shadow); padding: 20px; margin-bottom: 20px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th, td { padding: 10px 8px; text-align: right; border-bottom: 1px solid var(--border); }
  th { color: var(--text-muted); font-weight: 600; }
  .empty-state { text-align: center; padding: 50px 20px; }
  .empty-icon { font-size: 2.5rem; margin-bottom: 10px; }
  .debug-warning { background: #FEF3C7; color: #92400E; border: 1px solid #FDE68A; border-radius: 10px; padding: 12px 16px; margin-bottom: 20px; font-size: 0.85rem; }
  .back { margin-top: 10px; }
  .back a { color: var(--accent); text-decoration: none; font-size: 0.9rem; }
  .back a:hover { text-decoration: underline; }
</style>
</head>
<body>${bodyHtml}</body>
</html>`,
  };
}

function fmt(n) {
  if (n === undefined || n === null) return "0";
  return Number(n).toLocaleString('en-US');
}

function sum(arr, key) {
  return arr.reduce((s, r) => s + (r[key] || 0), 0);
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

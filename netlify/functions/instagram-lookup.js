// netlify/functions/instagram-lookup.js
// Looks up an Instagram Business/Creator account by username via the
// Instagram Platform API (Instagram Login, graph.instagram.com):
//   - Any public Business/Creator account: general stats only (followers,
//     media count, profile picture) via Business Discovery — Instagram
//     does not allow listing another account's individual posts.
//   - Our own connected account (whichever username the access token
//     belongs to): the same stats, plus the latest 15 posts with their
//     like/comment counts.
//
// Required env vars (set in Netlify, never hardcoded here):
// - INSTAGRAM_ACCESS_TOKEN: a short-lived (~1 hour) Instagram User Access
//   Token, generated from the Meta App dashboard. Only ever needed again
//   here if the stored long-lived token is lost or fully expires.
// - INSTAGRAM_APP_SECRET: the Meta App's secret, used only to exchange the
//   short-lived token for a long-lived one (~60 days).
// - TOKEN_ENCRYPTION_KEY: same 32-byte hex key already used to encrypt
//   TikTok refresh tokens (see _crypto.js) — reused here to encrypt the
//   stored long-lived Instagram token at rest.
//
// Token lifecycle (fully automatic, no manual exchange needed):
//   1. First call ever: exchanges INSTAGRAM_ACCESS_TOKEN (short-lived) for
//      a long-lived token via ig_exchange_token, and stores it (encrypted)
//      in Netlify Blobs together with its expiry.
//   2. Every later call: reuses the stored long-lived token as long as
//      it's not close to expiring.
//   3. When the stored token has less than ~5 days left, it's proactively
//      refreshed via ig_refresh_token (extends it another ~60 days) before
//      being used, so it never needs the short-lived token again.
//   4. If the stored token is missing/expired outright, falls back to
//      exchanging INSTAGRAM_ACCESS_TOKEN again — so updating that env var
//      with a fresh short-lived token and re-deploying is always enough
//      to recover.
//
// GET /.netlify/functions/instagram-lookup?q=<username>

const { getSessionUser } = require("./_auth");
const { checkRateLimit, getClientIp } = require("./_rate-limit");
const { getSettingsStore } = require("./_blobs-store");
const { encrypt, decrypt } = require("./_crypto");

const IG_HOST = "https://graph.instagram.com";
const IG_VERSION = "v21.0";
const TOKEN_BLOB_KEY = "instagram-long-lived-token";
const MAX_POSTS = 15;

// لو باقي أقل من هذا على انتهاء التوكن المخزّن، نعتبره منتهي ونبدّل
// توكن جديد من الصفر بدل استخدامه.
const EXPIRY_SAFETY_MS = 60 * 60 * 1000; // ساعة
// لو باقي أقل من هذا، نجدده استباقيًا (ig_refresh_token) قبل الاستخدام.
const REFRESH_BEFORE_MS = 5 * 24 * 60 * 60 * 1000; // 5 أيام

// يبني رسالة خطأ من استجابة Meta الخام — نطبع الجسم الكامل باللوق،
// ونرجّع الجسم الكامل أيضًا بالرسالة المعروضة بالواجهة مباشرة (مو بس
// ملخّص)، عشان تقدر تشوف كل تفاصيل الخطأ الحقيقية بدون فتح أي سجلات.
function describeMetaError(step, status, data) {
  const raw = JSON.stringify(data);
  console.error(`instagram-lookup: [${step}] Meta API error — status=${status} raw=${raw}`);
  return `فشل بخطوة "${step}" (HTTP ${status}) — استجابة Meta الكاملة: ${raw}`;
}

async function igFetch(step, path, params, accessToken) {
  const url = new URL(`${IG_HOST}/${IG_VERSION}/${path}`);
  Object.entries(params || {}).forEach(([key, value]) => url.searchParams.set(key, value));
  url.searchParams.set("access_token", accessToken);

  const res = await fetch(url.toString());
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const err = new Error(describeMetaError(step, res.status, data));
    err.status = res.status >= 400 && res.status < 500 ? 400 : 502;
    throw err;
  }
  return data;
}

async function exchangeForLongLivedToken(shortLivedToken) {
  const appSecret = process.env.INSTAGRAM_APP_SECRET;
  if (!appSecret) {
    throw Object.assign(new Error("متغير INSTAGRAM_APP_SECRET غير مُعد بإعدادات الخادم."), { status: 500 });
  }
  const url = new URL(`${IG_HOST}/access_token`);
  url.searchParams.set("grant_type", "ig_exchange_token");
  url.searchParams.set("client_secret", appSecret);
  url.searchParams.set("access_token", shortLivedToken);

  const res = await fetch(url.toString());
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.access_token) {
    throw Object.assign(new Error(describeMetaError("تبديل التوكن لـ long-lived (ig_exchange_token)", res.status, data)), { status: 502 });
  }
  return data; // { access_token, token_type, expires_in }
}

async function refreshLongLivedToken(longLivedToken) {
  const url = new URL(`${IG_HOST}/refresh_access_token`);
  url.searchParams.set("grant_type", "ig_refresh_token");
  url.searchParams.set("access_token", longLivedToken);

  const res = await fetch(url.toString());
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.access_token) {
    throw Object.assign(new Error(describeMetaError("تجديد التوكن (ig_refresh_token)", res.status, data)), { status: 502 });
  }
  return data; // { access_token, token_type, expires_in }
}

async function storeToken(accessToken, expiresInSeconds) {
  const expires_at = Date.now() + Number(expiresInSeconds || 0) * 1000;
  try {
    const store = getSettingsStore();
    await store.setJSON(TOKEN_BLOB_KEY, { token_enc: encrypt(accessToken), expires_at, stored_at: Date.now() });
  } catch (err) {
    // غالبًا TOKEN_ENCRYPTION_KEY غير مُعد. نكمل بدون تخزين دائم — الطلب
    // الحالي يشتغل عادي، وبس الطلب الجاي بيعيد التبديل من جديد.
    console.error("instagram-lookup: failed to persist long-lived token:", err);
  }
}

// يرجع توكن وصول صالح للاستخدام الآن، مع التكفل بكل دورة حياة التوكن
// (تبديل أول مرة، إعادة استخدام، تجديد استباقي) تلقائيًا.
async function getValidAccessToken() {
  const store = getSettingsStore();
  const stored = await store.get(TOKEN_BLOB_KEY, { type: "json" }).catch(() => null);

  if (stored && stored.token_enc && stored.expires_at) {
    const msRemaining = stored.expires_at - Date.now();
    if (msRemaining > EXPIRY_SAFETY_MS) {
      let token = decrypt(stored.token_enc);
      if (msRemaining < REFRESH_BEFORE_MS) {
        try {
          const refreshed = await refreshLongLivedToken(token);
          await storeToken(refreshed.access_token, refreshed.expires_in);
          token = refreshed.access_token;
        } catch (err) {
          // فشل التجديد الاستباقي — نكمل بالتوكن الحالي طالما لسه صالح.
          console.error("instagram-lookup: proactive token refresh failed:", err);
        }
      }
      return token;
    }
  }

  // ما فيه توكن مخزّن صالح: نستخدم توكن متغير البيئة.
  const envToken = process.env.INSTAGRAM_ACCESS_TOKEN;
  if (!envToken) {
    throw Object.assign(new Error("متغير INSTAGRAM_ACCESS_TOKEN غير مُعد بإعدادات الخادم."), { status: 500 });
  }

  // مهم: تبديله لـ long-lived خطوة "تحسين" منفصلة، مو شرط لنجاح الطلب.
  // لو فشلت (سر التطبيق غلط، أو التوكن نفسه غير مؤهل للتبديل لأي سبب)،
  // ما نوقف طلب المستخدم الحالي — نكمل بتوكن متغير البيئة الخام مباشرة،
  // ونسجّل سبب فشل التبديل فقط. هذا يفصل مشكلة "التبديل" عن مشكلة
  // "الاستخدام الفعلي"، فلو نجح البحث بعدها نعرف يقينًا إن العلة
  // بخطوة ig_exchange_token تحديدًا لا بباقي الكود.
  try {
    const exchanged = await exchangeForLongLivedToken(envToken);
    await storeToken(exchanged.access_token, exchanged.expires_in);
    return exchanged.access_token;
  } catch (err) {
    console.error("instagram-lookup: token exchange failed, falling back to raw INSTAGRAM_ACCESS_TOKEN for this request:", err.message);
    return envToken;
  }
}

async function fetchOwnPosts(accessToken) {
  const mediaData = await igFetch(
    "جلب آخر المنشورات (/me/media)",
    "me/media",
    { fields: "id,caption,media_type,media_url,thumbnail_url,permalink,timestamp,like_count,comments_count", limit: String(MAX_POSTS) },
    accessToken
  );
  return (mediaData.data || []).map((m) => ({
    id: m.id,
    caption: m.caption || "",
    permalink: m.permalink || "",
    thumbnail: m.media_type === "VIDEO" ? m.thumbnail_url || m.media_url || "" : m.media_url || "",
    like_count: m.like_count != null ? Number(m.like_count) : null,
    comment_count: m.comments_count != null ? Number(m.comments_count) : null,
  }));
}

exports.handler = async function (event) {
  const jsonHeaders = { "Content-Type": "application/json", "Cache-Control": "no-store" };

  const user = getSessionUser(event);
  if (!user) {
    return { statusCode: 401, headers: jsonHeaders, body: JSON.stringify({ error: "Not authenticated" }) };
  }

  const ip = getClientIp(event);
  const rate = await checkRateLimit(`instagram-lookup:${ip}`, 20, 600);
  if (!rate.allowed) {
    return { statusCode: 429, headers: jsonHeaders, body: JSON.stringify({ error: "طلبات كثيرة، حاول بعد شوي." }) };
  }

  const q = ((event.queryStringParameters && event.queryStringParameters.q) || "").trim().replace(/^@/, "");
  if (!q) {
    return { statusCode: 400, headers: jsonHeaders, body: JSON.stringify({ error: "اكتب اسم المستخدم (username)." }) };
  }

  try {
    const accessToken = await getValidAccessToken();

    const me = await igFetch(
      "جلب بيانات الحساب المتصل (/me)",
      "me",
      { fields: "id,username,name,account_type,media_count,followers_count,profile_picture_url" },
      accessToken
    );

    const isOwnAccount = q.toLowerCase() === (me.username || "").toLowerCase();

    if (isOwnAccount) {
      const posts = await fetchOwnPosts(accessToken);
      return {
        statusCode: 200,
        headers: jsonHeaders,
        body: JSON.stringify({
          account: {
            username: me.username || q,
            name: me.name || "",
            profile_picture: me.profile_picture_url || "",
            followers_count: me.followers_count != null ? Number(me.followers_count) : null,
            media_count: Number(me.media_count || 0),
            is_own: true,
          },
          posts,
        }),
      };
    }

    // حساب ثاني: Business Discovery — إحصائيات عامة بس، إنستقرام ما
    // يسمح بجلب قائمة منشورات حساب غير حسابنا.
    const discovery = await igFetch(
      "البحث عن الحساب (business_discovery)",
      me.id,
      { fields: `business_discovery.username(${q}){username,name,followers_count,media_count,profile_picture_url}` },
      accessToken
    );
    const bd = discovery.business_discovery;
    if (!bd) {
      return {
        statusCode: 404,
        headers: jsonHeaders,
        body: JSON.stringify({ error: "ما لقينا حساب Business/Creator بهذا الاسم، أو الحساب خاص." }),
      };
    }

    return {
      statusCode: 200,
      headers: jsonHeaders,
      body: JSON.stringify({
        account: {
          username: bd.username || q,
          name: bd.name || "",
          profile_picture: bd.profile_picture_url || "",
          followers_count: bd.followers_count != null ? Number(bd.followers_count) : null,
          media_count: Number(bd.media_count || 0),
          is_own: false,
        },
        posts: [],
      }),
    };
  } catch (err) {
    console.error("instagram-lookup: failed for query", q, err);
    return {
      statusCode: err.status || 502,
      headers: jsonHeaders,
      body: JSON.stringify({ error: err.message || "تعذر الاتصال بـ Instagram API." }),
    };
  }
};

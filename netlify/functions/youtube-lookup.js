// netlify/functions/youtube-lookup.js
// Looks up a YouTube channel (by name, URL, or @handle) via the YouTube
// Data API v3, and returns the channel's stats plus its latest videos
// (each with its own view/like/comment counts and publish date).
//
// Required env var (set in Netlify, never hardcoded here):
// - YOUTUBE_API_KEY: a YouTube Data API v3 key (https://console.cloud.google.com/).
//
// GET /.netlify/functions/youtube-lookup?q=<name|url|@handle>

const { getSessionUser } = require("./_auth");
const { checkRateLimit, getClientIp } = require("./_rate-limit");

const YT_API_BASE = "https://www.googleapis.com/youtube/v3";
const MAX_VIDEOS = 15;

async function ytFetch(path, params, apiKey) {
  const url = new URL(`${YT_API_BASE}/${path}`);
  Object.entries(params).forEach(([key, value]) => url.searchParams.set(key, value));
  url.searchParams.set("key", apiKey);

  const res = await fetch(url.toString());
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const message = (data && data.error && data.error.message) || `YouTube API error (${res.status})`;
    const err = new Error(message);
    err.status = res.status >= 400 && res.status < 500 ? 400 : 502;
    throw err;
  }
  return data;
}

// يقبل اسم قناة، أو رابط (youtube.com/@handle، /channel/UCxxx، /c/Name،
// /user/Name)، أو @handle مباشرة، ويرجع النص المهم للبحث عنه فقط.
function parseChannelQuery(raw) {
  const trimmed = (raw || "").trim();
  if (!trimmed) return "";

  try {
    const url = new URL(trimmed.match(/^https?:\/\//i) ? trimmed : `https://${trimmed}`);
    const host = url.hostname.replace(/^www\./i, "").replace(/^m\./i, "");
    if (host === "youtube.com" || host === "youtu.be") {
      const parts = url.pathname.split("/").filter(Boolean);
      if (!parts.length) return trimmed;
      if ((parts[0] === "channel" || parts[0] === "c" || parts[0] === "user") && parts[1]) {
        return decodeURIComponent(parts[1]);
      }
      return decodeURIComponent(parts[0]);
    }
  } catch (e) {
    // مو رابط صالح — نكمل ونعتبره اسم/handle كما هو.
  }
  return trimmed;
}

// يحاول عدة طرق للوصول للقناة الصحيحة: معرّف قناة مباشر، @handle، اسم
// مستخدم قديم (forUsername)، وأخيرًا بحث عام (search) كحل احتياطي.
async function resolveChannel(rawQuery, apiKey) {
  const q = parseChannelQuery(rawQuery);
  if (!q) return null;
  const parts = "snippet,statistics,contentDetails";

  if (/^UC[\w-]{22}$/.test(q)) {
    const data = await ytFetch("channels", { part: parts, id: q }, apiKey);
    if (data.items && data.items.length) return data.items[0];
  }

  const looksLikeHandle = q.startsWith("@") || (/^[\w.-]+$/.test(q) && !q.includes(" "));
  if (looksLikeHandle) {
    const handle = q.startsWith("@") ? q : `@${q}`;
    const data = await ytFetch("channels", { part: parts, forHandle: handle }, apiKey).catch(() => null);
    if (data && data.items && data.items.length) return data.items[0];
  }

  if (!q.includes(" ")) {
    const dataUser = await ytFetch("channels", { part: parts, forUsername: q }, apiKey).catch(() => null);
    if (dataUser && dataUser.items && dataUser.items.length) return dataUser.items[0];
  }

  const searchData = await ytFetch("search", { part: "snippet", type: "channel", q, maxResults: 1 }, apiKey);
  const firstMatch = searchData.items && searchData.items[0];
  if (!firstMatch) return null;
  const channelId = (firstMatch.snippet && firstMatch.snippet.channelId) || (firstMatch.id && firstMatch.id.channelId);
  if (!channelId) return null;

  const data = await ytFetch("channels", { part: parts, id: channelId }, apiKey);
  return (data.items && data.items[0]) || null;
}

function thumbnailUrl(thumbnails) {
  if (!thumbnails) return "";
  return (thumbnails.medium || thumbnails.high || thumbnails.default || {}).url || "";
}

async function fetchLatestVideos(uploadsPlaylistId, apiKey) {
  if (!uploadsPlaylistId) return [];

  const playlistData = await ytFetch(
    "playlistItems",
    { part: "contentDetails", playlistId: uploadsPlaylistId, maxResults: MAX_VIDEOS },
    apiKey
  );
  const videoIds = (playlistData.items || [])
    .map((item) => item.contentDetails && item.contentDetails.videoId)
    .filter(Boolean);
  if (!videoIds.length) return [];

  const videosData = await ytFetch("videos", { part: "snippet,statistics", id: videoIds.join(",") }, apiKey);

  // videos.list ما يضمن رجوع النتائج بنفس ترتيب المعرفات المطلوبة، فنعيد
  // ترتيبها حسب ترتيب النشر الأصلي من playlistItems (الأحدث أولًا).
  const orderIndex = new Map(videoIds.map((id, i) => [id, i]));
  const videos = (videosData.items || []).map((v) => ({
    id: v.id,
    title: (v.snippet && v.snippet.title) || "",
    thumbnail: thumbnailUrl(v.snippet && v.snippet.thumbnails),
    published_at: (v.snippet && v.snippet.publishedAt) || null,
    view_count: Number((v.statistics && v.statistics.viewCount) || 0),
    like_count: v.statistics && v.statistics.likeCount != null ? Number(v.statistics.likeCount) : null,
    comment_count: v.statistics && v.statistics.commentCount != null ? Number(v.statistics.commentCount) : null,
  }));
  videos.sort((a, b) => (orderIndex.get(a.id) ?? 0) - (orderIndex.get(b.id) ?? 0));
  return videos;
}

exports.handler = async function (event) {
  const jsonHeaders = { "Content-Type": "application/json", "Cache-Control": "no-store" };

  const user = getSessionUser(event);
  if (!user) {
    return { statusCode: 401, headers: jsonHeaders, body: JSON.stringify({ error: "Not authenticated" }) };
  }

  const ip = getClientIp(event);
  const rate = await checkRateLimit(`youtube-lookup:${ip}`, 20, 600);
  if (!rate.allowed) {
    return {
      statusCode: 429,
      headers: jsonHeaders,
      body: JSON.stringify({ error: "طلبات كثيرة، حاول بعد شوي." }),
    };
  }

  const apiKey = process.env.YOUTUBE_API_KEY;
  if (!apiKey) {
    return {
      statusCode: 500,
      headers: jsonHeaders,
      body: JSON.stringify({ error: "متغير YOUTUBE_API_KEY غير مُعد بإعدادات الخادم." }),
    };
  }

  const q = ((event.queryStringParameters && event.queryStringParameters.q) || "").trim();
  if (!q) {
    return {
      statusCode: 400,
      headers: jsonHeaders,
      body: JSON.stringify({ error: "اكتب اسم القناة أو رابطها أو معرّف @." }),
    };
  }

  try {
    const channel = await resolveChannel(q, apiKey);
    if (!channel) {
      return {
        statusCode: 404,
        headers: jsonHeaders,
        body: JSON.stringify({ error: "ما لقينا قناة يوتيوب بهذا الاسم/الرابط." }),
      };
    }

    const uploadsPlaylistId =
      channel.contentDetails && channel.contentDetails.relatedPlaylists && channel.contentDetails.relatedPlaylists.uploads;
    const videos = await fetchLatestVideos(uploadsPlaylistId, apiKey);

    const stats = channel.statistics || {};
    const responseBody = {
      channel: {
        id: channel.id,
        title: (channel.snippet && channel.snippet.title) || "",
        customUrl: (channel.snippet && channel.snippet.customUrl) || "",
        thumbnail: thumbnailUrl(channel.snippet && channel.snippet.thumbnails),
        subscriber_count: stats.hiddenSubscriberCount ? null : Number(stats.subscriberCount || 0),
        view_count: Number(stats.viewCount || 0),
        video_count: Number(stats.videoCount || 0),
      },
      videos,
    };

    return { statusCode: 200, headers: jsonHeaders, body: JSON.stringify(responseBody) };
  } catch (err) {
    console.error("youtube-lookup: failed for query", q, err);
    return {
      statusCode: err.status || 502,
      headers: jsonHeaders,
      body: JSON.stringify({ error: err.message || "تعذر الاتصال بـ YouTube API." }),
    };
  }
};

// netlify/functions/sync-tiktok.js
// Scheduled function (runs automatically every hour) that, for every
// connected TikTok account:
//   1. Uses the stored (encrypted) refresh token to get a fresh access token
//   2. Re-fetches the user's stats and video list
//   3. Overwrites the stored video list with the fresh one — any video that
//      was deleted on TikTok simply won't be in the new list anymore, so it
//      disappears from the dashboard automatically.
//   4. Stores the new refresh token (TikTok rotates it on every refresh)
//
// If a refresh fails (e.g. the user revoked access), the account is marked
// sync_status: "needs_reconnect" instead of being deleted, so historical
// data isn't lost and the dashboard can prompt the user to reconnect.

const { schedule } = require("@netlify/functions");
const { getAccountsStore } = require("./_blobs-store");
const { encrypt, decrypt } = require("./_crypto");

async function syncAllAccounts() {
  const CLIENT_KEY = process.env.TIKTOK_CLIENT_KEY;
  const CLIENT_SECRET = process.env.TIKTOK_CLIENT_SECRET_V2;

  if (!CLIENT_KEY || !CLIENT_SECRET) {
    console.error("sync-tiktok: missing TIKTOK_CLIENT_KEY / TIKTOK_CLIENT_SECRET_V2");
    return { statusCode: 500, body: "Missing TikTok credentials" };
  }

  const store = getAccountsStore();
  const { blobs } = await store.list();

  const results = [];

  for (const blob of blobs) {
    const account = await store.get(blob.key, { type: "json" }).catch(() => null);
    if (!account || account.platform !== "tiktok") continue;

    if (!account.refresh_token_enc) {
      // No refresh token stored (e.g. connected before this feature existed,
      // or encryption key wasn't configured at connect time). Can't
      // auto-sync — leave as-is.
      results.push({ open_id: account.open_id, status: "skipped_no_token" });
      continue;
    }

    try {
      const refreshToken = decrypt(account.refresh_token_enc);

      const tokenRes = await fetch("https://open.tiktokapis.com/v2/oauth/token/", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_key: CLIENT_KEY,
          client_secret: CLIENT_SECRET,
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }),
      });
      const tokenData = await tokenRes.json();

      if (!tokenData.access_token) {
        // Refresh failed — token was likely revoked by the user.
        await store.setJSON(blob.key, {
          ...account,
          sync_status: "needs_reconnect",
          last_synced_at: new Date().toISOString(),
        });
        results.push({ open_id: account.open_id, status: "needs_reconnect" });
        continue;
      }

      const accessToken = tokenData.access_token;

      const [userRes, videoRes] = await Promise.all([
        fetch(
          "https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name,avatar_url,follower_count,following_count,likes_count,video_count",
          { headers: { Authorization: `Bearer ${accessToken}` } }
        ),
        fetch(
          "https://open.tiktokapis.com/v2/video/list/?fields=id,title,create_time,cover_image_url,share_url,view_count,like_count,comment_count,share_count",
          {
            method: "POST",
            headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
            body: JSON.stringify({ max_count: 20 }),
          }
        ),
      ]);

      const userData = await userRes.json();
      const videoData = await videoRes.json();
      const user = (userData.data && userData.data.user) || {};
      const videos = (videoData.data && videoData.data.videos) || [];

      const updated = {
        ...account,
        display_name: user.display_name || account.display_name,
        avatar_url: user.avatar_url || account.avatar_url,
        follower_count: user.follower_count || 0,
        following_count: user.following_count || 0,
        likes_count: user.likes_count || 0,
        video_count: user.video_count || 0,
        // Full replacement — any video missing from this fresh list (i.e.
        // deleted on TikTok) is dropped from what we store, so it
        // disappears from the dashboard automatically.
        videos: videos.slice(0, 20).map((v) => ({
          id: v.id || "",
          title: v.title || "",
          view_count: v.view_count || 0,
          like_count: v.like_count || 0,
          comment_count: v.comment_count || 0,
          share_count: v.share_count || 0,
          // TikTok returns create_time as a Unix timestamp (seconds). We
          // convert it to an ISO string so the dashboard can compare it
          // against a campaign marker date to split videos into
          // "before" / "after" groups.
          create_time: v.create_time ? new Date(v.create_time * 1000).toISOString() : null,
        })),
        last_synced_at: new Date().toISOString(),
        sync_status: "ok",
      };

      if (tokenData.refresh_token) {
        updated.refresh_token_enc = encrypt(tokenData.refresh_token);
      }

      await store.setJSON(blob.key, updated);
      results.push({ open_id: account.open_id, status: "synced", videos: updated.videos.length });
    } catch (err) {
      console.error(`sync-tiktok: failed for ${account.open_id}:`, err);
      results.push({ open_id: account.open_id, status: "error", error: String((err && err.message) || err) });
    }
  }

  console.log("sync-tiktok results:", JSON.stringify(results));
  return { statusCode: 200, body: JSON.stringify({ synced: results.length, results }) };
}

// Runs automatically every 15 minutes — a balance between fresh data and
// staying well under TikTok's rate limits and Netlify's function-invocation
// quota. Netlify also lets you trigger it manually from the Functions tab
// in the dashboard for testing.
exports.handler = schedule("*/15 * * * *", async () => {
  return syncAllAccounts();
});

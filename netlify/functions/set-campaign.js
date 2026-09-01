// netlify/functions/set-campaign.js
// Saves (or clears) a "campaign marker" — a date and short label — on a
// connected account. The dashboard uses this to split that account's videos
// into "before" and "after" groups and compare their average performance.
//
// Access control: same rule as the rest of the app — admins can edit any
// account, members only accounts they personally connected.

const { getAccountsStore } = require("./_blobs-store");
const { checkRateLimit, getClientIp } = require("./_rate-limit");
const { getSessionUser } = require("./_auth");

exports.handler = async function (event) {
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers: { "Content-Type": "application/json", Allow: "POST" },
      body: JSON.stringify({ error: "Method not allowed" }),
    };
  }

  const user = getSessionUser(event);
  if (!user) {
    return {
      statusCode: 401,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Not authenticated" }),
    };
  }

  const ip = getClientIp(event);
  const rate = await checkRateLimit(`campaign:${ip}`, 30, 600);
  if (!rate.allowed) {
    return {
      statusCode: 429,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Too many requests, please wait a bit." }),
    };
  }

  let payload;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch (e) {
    return {
      statusCode: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Invalid JSON body" }),
    };
  }

  const { open_id, campaign_date, campaign_label } = payload;

  if (!open_id) {
    return {
      statusCode: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Missing open_id" }),
    };
  }

  // campaign_date must be a valid date string (YYYY-MM-DD) or null/empty to
  // clear the marker.
  if (campaign_date) {
    const parsed = new Date(campaign_date);
    if (isNaN(parsed.getTime())) {
      return {
        statusCode: 400,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: "Invalid campaign_date" }),
      };
    }
  }

  try {
    const store = getAccountsStore();
    const existing = await store.get(open_id, { type: "json" }).catch(() => null);

    if (!existing) {
      return {
        statusCode: 404,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: "Account not found" }),
      };
    }

    const isOwner = existing.connected_by === user.username;
    if (user.role !== "admin" && !isOwner) {
      return {
        statusCode: 403,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: "ما عندك صلاحية تعدل هذا الحساب." }),
      };
    }

    const updated = {
      ...existing,
      campaign: campaign_date
        ? {
            date: new Date(campaign_date).toISOString(),
            label: (campaign_label || "").toString().slice(0, 100),
          }
        : null,
    };

    await store.setJSON(open_id, updated);

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ success: true, campaign: updated.campaign }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: String(err) }),
    };
  }
};

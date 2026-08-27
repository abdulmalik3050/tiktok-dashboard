// netlify/functions/delete-account.js
// Removes a stored TikTok account (by open_id) from Netlify Blobs.
// Called from accounts.html when the user clicks "remove" on an account card.
//
// Access control: admins can delete any account. Members can only delete
// accounts they personally connected (checked via connected_by).

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
  const rate = await checkRateLimit(`delete:${ip}`, 30, 600);
  if (!rate.allowed) {
    return {
      statusCode: 429,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Too many requests, please wait a bit." }),
    };
  }

  const openId = event.queryStringParameters && event.queryStringParameters.open_id;

  if (!openId) {
    return {
      statusCode: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Missing open_id parameter" }),
    };
  }

  try {
    const store = getAccountsStore();
    const existing = await store.get(openId, { type: "json" }).catch(() => null);

    if (!existing) {
      return {
        statusCode: 404,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: "Account not found" }),
      };
    }

    // Access control: admins can remove any account. Members can only
    // remove accounts they personally connected.
    const isOwner = existing.connected_by === user.username;
    if (user.role !== "admin" && !isOwner) {
      return {
        statusCode: 403,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: "ما عندك صلاحية تحذف هذا الحساب." }),
      };
    }

    await store.delete(openId);
    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ success: true }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: String(err) }),
    };
  }
};

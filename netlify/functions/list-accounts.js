// netlify/functions/list-accounts.js
// Returns all TikTok accounts currently stored in Netlify Blobs, as JSON.
// Used by accounts.html to render the multi-account dashboard.
// Requires a valid logged-in session.

const { getAccountsStore } = require("./_blobs-store");
const { checkRateLimit, getClientIp } = require("./_rate-limit");
const { getSessionUser } = require("./_auth");

exports.handler = async function (event) {
  const user = getSessionUser(event);
  if (!user) {
    return {
      statusCode: 401,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Not authenticated" }),
    };
  }

  const ip = getClientIp(event);
  const rate = await checkRateLimit(`list:${ip}`, 60, 600);
  if (!rate.allowed) {
    return {
      statusCode: 429,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Too many requests, please wait a bit." }),
    };
  }

  try {
    const store = getAccountsStore();
    const { blobs } = await store.list();

    const accounts = await Promise.all(
      blobs.map(async (b) => {
        try {
          return await store.get(b.key, { type: "json" });
        } catch (e) {
          return null;
        }
      })
    );

    const cleanAccounts = accounts.filter(Boolean);

    // Access control: admins see every account. Regular members only see
    // accounts they personally connected (tracked via connected_by, set
    // when the account was linked in tiktok-callback.js). Accounts
    // connected before this field existed have no owner and are only
    // visible to admins, since we can't attribute them to anyone.
    const visibleAccounts =
      user.role === "admin"
        ? cleanAccounts
        : cleanAccounts.filter((a) => a.connected_by === user.username);

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
      body: JSON.stringify({ accounts: visibleAccounts, role: user.role }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: String(err) }),
    };
  }
};

// netlify/functions/auth-setup.js
// One-time bootstrap: creates the FIRST admin user for the dashboard.
// Only works if:
//   1. No users exist yet in the "app-users" store, AND
//   2. The request includes the correct DASHBOARD_SETUP_TOKEN (set as a
//      Netlify env var — treat it like a temporary master password).
//
// After the first admin is created, this endpoint refuses all further
// requests, so it's safe to leave deployed.

const { getUsersStore } = require("./_blobs-store");
const { hashPassword } = require("./_auth");
const { checkRateLimit, getClientIp } = require("./_rate-limit");

exports.handler = async function (event) {
  if (event.httpMethod !== "POST") {
    return json(405, { error: "Method not allowed" });
  }

  const ip = getClientIp(event);
  const rate = await checkRateLimit(`setup:${ip}`, 10, 600);
  if (!rate.allowed) {
    return json(429, { error: "Too many requests, please wait a bit." });
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return json(400, { error: "Invalid request body" });
  }

  const { setup_token, username, password } = body;

  const expectedToken = process.env.DASHBOARD_SETUP_TOKEN;
  if (!expectedToken) {
    return json(500, { error: "DASHBOARD_SETUP_TOKEN is not configured on the server." });
  }
  if (!setup_token || setup_token !== expectedToken) {
    return json(403, { error: "Invalid setup token." });
  }

  if (!username || !password || password.length < 8) {
    return json(400, { error: "Username and a password of at least 8 characters are required." });
  }

  const store = getUsersStore();
  const { blobs } = await store.list();

  if (blobs.length > 0) {
    return json(403, { error: "Setup already completed — an admin account already exists." });
  }

  const { salt, hash } = hashPassword(password);
  await store.setJSON(username.toLowerCase(), {
    username,
    salt,
    hash,
    role: "admin",
    created_at: new Date().toISOString(),
  });

  return json(200, { success: true });
};

function json(statusCode, body) {
  return { statusCode, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}

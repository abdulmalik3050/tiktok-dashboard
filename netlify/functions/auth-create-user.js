// netlify/functions/auth-create-user.js
// Lets an already-logged-in admin create additional user accounts for
// coworkers. Requires a valid admin session — cannot be used to self-register.

const { getUsersStore } = require("./_blobs-store");
const { hashPassword, getSessionUser } = require("./_auth");
const { checkRateLimit, getClientIp } = require("./_rate-limit");

exports.handler = async function (event) {
  if (event.httpMethod !== "POST") {
    return json(405, { error: "Method not allowed" });
  }

  const currentUser = getSessionUser(event);
  if (!currentUser || currentUser.role !== "admin") {
    return json(403, { error: "هذا الإجراء متاح للمدير (admin) فقط." });
  }

  const ip = getClientIp(event);
  const rate = await checkRateLimit(`create-user:${ip}`, 20, 600);
  if (!rate.allowed) {
    return json(429, { error: "Too many requests, please wait a bit." });
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return json(400, { error: "Invalid request body" });
  }

  const { username, password, role } = body;
  if (!username || !password || password.length < 8) {
    return json(400, { error: "اسم مستخدم وكلمة مرور (٨ أحرف على الأقل) مطلوبة." });
  }

  const store = getUsersStore();
  const key = String(username).toLowerCase();
  const existing = await store.get(key, { type: "json" }).catch(() => null);
  if (existing) {
    return json(409, { error: "اسم المستخدم موجود مسبقًا." });
  }

  const { salt, hash } = hashPassword(password);
  await store.setJSON(key, {
    username,
    salt,
    hash,
    role: role === "admin" ? "admin" : "member",
    created_at: new Date().toISOString(),
    created_by: currentUser.username,
  });

  return json(200, { success: true });
};

function json(statusCode, body) {
  return { statusCode, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}

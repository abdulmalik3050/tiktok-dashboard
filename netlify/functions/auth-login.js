// netlify/functions/auth-login.js
// Verifies username/password against the "app-users" store and, on
// success, issues a signed httpOnly session cookie.

const { getUsersStore } = require("./_blobs-store");
const { verifyPassword, createSessionCookie } = require("./_auth");
const { checkRateLimit, getClientIp } = require("./_rate-limit");

exports.handler = async function (event) {
  if (event.httpMethod !== "POST") {
    return json(405, { error: "Method not allowed" });
  }

  const ip = getClientIp(event);
  // Deliberately strict: login attempts are the most sensitive endpoint.
  const rate = await checkRateLimit(`login-attempt:${ip}`, 10, 600);
  if (!rate.allowed) {
    return json(429, { error: "محاولات كثيرة جدًا، الرجاء الانتظار قليلاً." });
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return json(400, { error: "Invalid request body" });
  }

  const { username, password } = body;
  if (!username || !password) {
    return json(400, { error: "الرجاء إدخال اسم المستخدم وكلمة المرور." });
  }

  try {
    const store = getUsersStore();
    const record = await store.get(String(username).toLowerCase(), { type: "json" }).catch(() => null);

    // Same error message whether the user doesn't exist or the password is
    // wrong — avoids leaking which usernames are registered.
    if (!record || !verifyPassword(password, record.salt, record.hash)) {
      return json(401, { error: "اسم المستخدم أو كلمة المرور غير صحيحة." });
    }

    return {
      statusCode: 200,
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": createSessionCookie({ username: record.username, role: record.role }),
      },
      body: JSON.stringify({ success: true, username: record.username, role: record.role }),
    };
  } catch (err) {
    return json(500, { error: String((err && err.message) || err) });
  }
};

function json(statusCode, body) {
  return { statusCode, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}

// netlify/functions/auth-logout.js
// Clears the session cookie.

const { clearSessionCookie } = require("./_auth");

exports.handler = async function () {
  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": clearSessionCookie(),
    },
    body: JSON.stringify({ success: true }),
  };
};

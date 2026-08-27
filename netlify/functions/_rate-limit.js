// netlify/functions/_rate-limit.js
// Simple IP-based rate limiter backed by Netlify Blobs. Not as fast as an
// in-memory/Redis limiter, but requires no extra infrastructure and is
// enough to blunt basic abuse (bots hammering the login/callback routes).

const { getRateLimitStore } = require("./_blobs-store");

/**
 * Returns { allowed: boolean, remaining: number } for the given key.
 * @param {string} key - usually `${routeName}:${ip}`
 * @param {number} limit - max requests allowed within the window
 * @param {number} windowSeconds - window length in seconds
 */
async function checkRateLimit(key, limit = 20, windowSeconds = 600) {
  try {
    const store = getRateLimitStore();
    const now = Date.now();
    const existing = await store.get(key, { type: "json" }).catch(() => null);

    let timestamps = (existing && existing.timestamps) || [];
    // Drop timestamps outside the current window.
    timestamps = timestamps.filter((t) => now - t < windowSeconds * 1000);

    if (timestamps.length >= limit) {
      return { allowed: false, remaining: 0 };
    }

    timestamps.push(now);
    await store.setJSON(key, { timestamps });

    return { allowed: true, remaining: limit - timestamps.length };
  } catch (err) {
    // If the rate limiter itself fails (e.g. Blobs misconfigured), fail
    // open rather than blocking legitimate users.
    console.error("Rate limit check failed:", err);
    return { allowed: true, remaining: limit };
  }
}

function getClientIp(event) {
  const headers = event.headers || {};
  const forwarded = headers["x-forwarded-for"] || headers["X-Forwarded-For"];
  if (forwarded) return forwarded.split(",")[0].trim();
  return (event.requestContext && event.requestContext.identity && event.requestContext.identity.sourceIp) || "unknown";
}

module.exports = { checkRateLimit, getClientIp };

// netlify/functions/_blobs-store.js
// Shared helper for accessing Netlify Blobs stores used by this app.
//
// On manual "drag & drop" deploys, Netlify does not automatically inject
// the Blobs context (siteID/token) the way it does for Git-linked or CLI
// deploys. To make Blobs work in that case, we fall back to manual
// configuration using NETLIFY_SITE_ID and NETLIFY_BLOBS_TOKEN env vars.

const { getStore } = require("@netlify/blobs");

function getNamedStore(name) {
  const siteID = process.env.NETLIFY_SITE_ID;
  const token = process.env.NETLIFY_BLOBS_TOKEN;

  if (siteID && token) {
    return getStore({ name, siteID, token });
  }

  // Fall back to automatic context (works for Git/CLI-based deploys).
  return getStore(name);
}

function getAccountsStore() {
  return getNamedStore("tiktok-accounts");
}

function getRateLimitStore() {
  return getNamedStore("rate-limits");
}

function getUsersStore() {
  return getNamedStore("app-users");
}

module.exports = { getAccountsStore, getRateLimitStore, getUsersStore };

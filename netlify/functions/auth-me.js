// netlify/functions/auth-me.js
// Reports the current session's user (if any), and whether the app has
// completed initial setup (i.e. whether an admin account exists yet).
// Used by login.html to decide whether to show the "first-time setup" form
// or the normal login form, and by protected pages to check auth status.

const { getUsersStore } = require("./_blobs-store");
const { getSessionUser } = require("./_auth");

exports.handler = async function (event) {
  const user = getSessionUser(event);

  let setupComplete = true;
  try {
    const store = getUsersStore();
    const { blobs } = await store.list();
    setupComplete = blobs.length > 0;
  } catch (err) {
    // If we can't check, assume setup is complete so we don't accidentally
    // expose the setup form in a broken state.
    setupComplete = true;
  }

  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    body: JSON.stringify({ authenticated: !!user, user: user || null, setupComplete }),
  };
};

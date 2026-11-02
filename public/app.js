const connectButton = document.querySelector("#connect");
const connectionStatus = document.querySelector("#connection-status");
const loginScreen = document.querySelector("#login-screen");
const dashboard = document.querySelector("#dashboard");
const loginForm = document.querySelector("#login-form");
const loginError = document.querySelector("#login-error");

function showLogin() {
  dashboard.hidden = true;
  loginScreen.hidden = false;
  document.querySelector("#dashboard-password").focus();
}
function showDashboard() {
  loginScreen.hidden = true;
  dashboard.hidden = false;
}
async function checkHealth() {
  const title = document.querySelector("#db-status");
  const detail = document.querySelector("#health-detail");
  try {
    const response = await fetch("/api/health");
    const data = await response.json();
    title.textContent = data.ok ? "Server online" : "Server issue";
    detail.textContent = data.databaseConfigured ? "Worker and D1 database detected." : "Database binding needs setup.";

    const connectionResponse = await fetch("/api/connection");
    if (connectionResponse.status === 401) {
      showLogin();
      return;
    }
    const connection = await connectionResponse.json();
    showDashboard();
    if (!data.kickCredentialsConfigured) {
      connectionStatus.textContent = "Kick credentials are missing from Worker settings.";
      connectButton.disabled = true;
    } else if (connection.connected) {
      connectionStatus.textContent = "Kick account connected. Granted scopes: " + (connection.scope || "not reported");
      connectButton.textContent = "Reconnect Kick";
    } else {
      connectionStatus.textContent = "Not connected to Kick yet.";
    }
  } catch {
    title.textContent = "Not deployed";
    detail.textContent = "Deploy the Worker to run the connection check.";
    showLogin();
  }
}
loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = document.querySelector("#login-button");
  const password = document.querySelector("#dashboard-password").value;
  button.disabled = true;
  loginError.textContent = "Checking password…";
  try {
    const response = await fetch("/api/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Login failed.");
    loginForm.reset();
    loginError.textContent = "";
    await checkHealth();
  } catch (error) {
    loginError.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
document.querySelector("#logout").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" });
  showLogin();
});
connectButton.addEventListener("click", () => {
  connectButton.disabled = true;
  connectionStatus.textContent = "Redirecting to Kick…";
  window.location.assign("/api/auth/start");
});
async function loadSpamSettings() {
  const status = document.querySelector("#settings-status");
  try {
    const response = await fetch("/api/settings");
    if (response.status === 401) { showLogin(); return; }
    const settings = await response.json();
    if (!response.ok) throw new Error(settings.error || "Could not load settings.");
    document.querySelector("#spam-enabled").checked = settings.spamEnabled;
    document.querySelector("#spam-repeat-count").value = settings.repeatCount;
    document.querySelector("#spam-window").value = settings.windowSeconds;
    document.querySelector("#spam-timeout").value = settings.timeoutSeconds;
    document.querySelector("#emote-message-threshold").value = settings.emoteMessageThreshold ?? 10;
    status.textContent = settings.spamEnabled ? "Settings loaded. Spam protection is enabled." : "Settings loaded. Rule is currently off.";
  } catch (error) {
    status.textContent = error.message;
  }
}
document.querySelector("#save-spam-settings").addEventListener("click", async () => {
  const button = document.querySelector("#save-spam-settings");
  const status = document.querySelector("#settings-status");
  const payload = {
    spamEnabled: document.querySelector("#spam-enabled").checked,
    repeatCount: Number(document.querySelector("#spam-repeat-count").value),
    windowSeconds: Number(document.querySelector("#spam-window").value),
    timeoutSeconds: Number(document.querySelector("#spam-timeout").value),
    emoteMessageThreshold: Number(document.querySelector("#emote-message-threshold").value)
  };
  button.disabled = true;
  status.textContent = "Saving settings…";
  try {
    const response = await fetch("/api/settings", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    if (response.status === 401) { showLogin(); throw new Error("Please log in again."); }
    if (!response.ok) throw new Error(result.error || "Could not save settings.");
    status.textContent = result.spamEnabled
      ? `Saved: ${result.repeatCount} repeats in ${result.windowSeconds}s → ${result.timeoutSeconds}s timeout. Emote threshold: ${result.emoteMessageThreshold} consecutive messages. Rule enabled.`
      : `Saved: ${result.repeatCount} repeats in ${result.windowSeconds}s → ${result.timeoutSeconds}s timeout. Emote threshold: ${result.emoteMessageThreshold} consecutive messages. Rule off.`;
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
async function loadChannels() {
  const status = document.querySelector("#channels-status");
  const list = document.querySelector("#channel-list");
  try {
    const response = await fetch("/api/channels");
    const data = await response.json();
    if (response.status === 401) { showLogin(); return; }
    if (!response.ok) throw new Error(data.error || "Could not load channels.");
    list.replaceChildren();
    if (!data.channels.length) { status.textContent = "No channels added yet."; return; }
    status.textContent = "Channels added: " + data.channels.length + ". Moderator permissions have not yet been verified."; 
    for (const channel of data.channels) {
      const item = document.createElement("div"); item.className = "channel-item";
      const name = document.createElement("strong"); name.textContent = "@" + channel.slug;
      const note = document.createElement("span"); note.textContent = "Added · protection OFF · permissions not checked";
      const remove = document.createElement("button"); remove.type = "button"; remove.textContent = "Remove"; remove.addEventListener("click", async () => {
        if (!confirm("Remove @" + channel.slug + " from managed channels?")) return;
        remove.disabled = true;
        const result = await fetch("/api/channels/" + channel.broadcasterUserId, { method: "DELETE" });
        if (result.ok) loadChannels(); else { remove.disabled = false; status.textContent = "Could not remove channel."; }
      });
      item.append(name, note, remove); list.append(item);
    }
  } catch (error) { status.textContent = error.message; }
}
document.querySelector("#add-channel-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.querySelector("#channel-slug");
  const button = document.querySelector("#add-channel-button");
  const status = document.querySelector("#channels-status");
  button.disabled = true; status.textContent = "Checking channel with Kick…";
  try {
    const response = await fetch("/api/channels", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ slug: input.value }) });
    const data = await response.json();
    if (response.status === 401) { showLogin(); throw new Error(data.error || "Reconnect Kick."); }
    if (!response.ok) throw new Error(data.error || "Could not add channel.");
    input.value = "";
    const subscriptionText = data.webhookSubscription === "subscribed"
      ? "Kick accepted the chat-event subscription."
      : "Kick subscription failed: " + (data.warning || "No reason returned.");
    await loadChannels();
    status.textContent = "@" + data.channel.slug + " added. " + subscriptionText + " Moderator permissions are NOT verified yet; protection remains off.";
  } catch (error) { status.textContent = error.message; }
  finally { button.disabled = false; }
});

document.querySelector("#check-moderation-results").addEventListener("click", async () => {
  const button = document.querySelector("#check-moderation-results");
  const status = document.querySelector("#moderation-results-status");
  const list = document.querySelector("#moderation-results-list");
  button.disabled = true;
  status.textContent = "Checking moderation results…";
  list.replaceChildren();
  try {
    const response = await fetch("/api/webhooks/diagnostics", { credentials: "same-origin", cache: "no-store" });
    const data = await response.json();
    if (response.status === 401) throw new Error("Your dashboard session was not accepted. Please log out and log in again.");
    if (!response.ok) throw new Error(data.error || "Could not load moderation results.");
    const matches = (data.diagnostics || []).filter(item =>
      ["dry_run_match", "dry_run_timeout"].includes(item.outcome)
    );
    if (!matches.length) {
      status.textContent = "No moderation matches recorded yet. Send a fresh test message and check again.";
      return;
    }
    status.textContent = "Showing " + matches.length + " recent dry-run match(es).";
    for (const result of matches) {
      let detail = {};
      try { detail = JSON.parse(result.detail || "{}"); } catch {}
      const item = document.createElement("div");
      item.className = "channel-item";
      const title = document.createElement("strong");
      title.textContent = (detail.username || "Unknown user") + " · " + result.stage;
      const summary = document.createElement("span");
      const action = detail.action === "would_timeout" ? "Would timeout for " + (detail.duration_seconds || 0) + " seconds"
        : detail.action === "would_permanently_ban" ? "Would permanently ban"
        : "Dry-run match";
      summary.textContent = "@" + (detail.channel || "unknown channel") + " — " + action + (detail.reason ? " · " + detail.reason : detail.matched_term ? " · Matched term: " + detail.matched_term : "");
      item.append(title, summary);
      list.append(item);
    }
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

document.querySelector("#check-webhook-events").addEventListener("click", async () => {
  const button = document.querySelector("#check-webhook-events");
  const status = document.querySelector("#webhook-status");
  const list = document.querySelector("#webhook-event-list");
  button.disabled = true;
  status.textContent = "Checking recent events…";
  list.replaceChildren();
  try {
    const response = await fetch("/api/webhooks/recent", { credentials: "same-origin", cache: "no-store" });
    const data = await response.json();
    if (response.status === 401) throw new Error("Your dashboard session was not accepted. Please log out and log in again.");
    if (!response.ok) throw new Error(data.error || "Could not load webhook events.");
    const events = data.events || [];
    if (!events.length) {
      const diagnosticResponse = await fetch("/api/webhooks/diagnostics", { credentials: "same-origin", cache: "no-store" });
      const diagnosticData = await diagnosticResponse.json();
      const latestError = (diagnosticData.diagnostics || []).find(item => item.outcome === "error");
      if (latestError) {
        status.textContent = "No chat events stored yet. Latest webhook error (" + latestError.stage + "): " + latestError.detail;
      } else {
        status.textContent = "No chat events received yet. No verification error has been recorded. Send a fresh chat message and check again.";
      }
      return;
    }
    status.textContent = "Received " + events.length + " recent event(s).";
    for (const event of events) {
      const item = document.createElement("div");
      item.className = "channel-item";
      const title = document.createElement("strong");
      title.textContent = (event.sender_username || "Unknown sender") + " · " + event.event_type;
      const detail = document.createElement("span");
      detail.textContent = "@" + (event.broadcaster_slug || "unknown channel") + " — " + (event.content || "(no message content)");
      item.append(title, detail);
      if (event.sender_user_id && event.broadcaster_user_id) {
        const timeout = document.createElement("button");
        timeout.type = "button";
        timeout.textContent = "Timeout";
        timeout.addEventListener("click", async () => {
          const minutesText = prompt("Timeout " + (event.sender_username || "user") + " for how many minutes? (1–10080)", "1");
          if (minutesText === null) return;
          const minutes = Number(minutesText);
          if (!Number.isInteger(minutes) || minutes < 1 || minutes > 10080) {
            status.textContent = "Enter a whole number from 1 to 10080 minutes.";
            return;
          }
          const targetName = event.sender_username || ("user ID " + event.sender_user_id);
          const channelName = event.broadcaster_slug || "this channel";
          if (!confirm("Send a " + minutes + "-minute timeout to " + targetName + " in " + channelName + "? This is a REAL Kick moderation action.")) return;
          timeout.disabled = true;
          status.textContent = "Sending timeout request to Kick…";
          try {
            const result = await fetch("/api/moderation/timeout", {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                broadcasterUserId: event.broadcaster_user_id,
                targetUserId: event.sender_user_id,
                username: event.sender_username || "",
                durationMinutes: minutes,
                reason: "Manual dashboard timeout"
              })
            });
            const body = await result.json();
            if (result.status === 401) { showLogin(); throw new Error(body.error || "Please reconnect Kick."); }
            if (!result.ok) throw new Error(body.error || "Kick rejected the timeout.");
            status.textContent = "Kick accepted: " + body.target + " timed out in @" + body.channel + " for " + body.durationMinutes + " minute(s).";
            timeout.textContent = "Timeout sent";
          } catch (error) {
            status.textContent = error.message;
            timeout.disabled = false;
          }
        });
        item.append(timeout);
        const ban = document.createElement("button");
        ban.type = "button";
        ban.textContent = "Permanent ban";
        ban.addEventListener("click", async () => {
          const targetName = event.sender_username || ("user ID " + event.sender_user_id);
          const channelName = event.broadcaster_slug || "this channel";
          const confirmationText = "PERMANENTLY BAN " + targetName;
          if (!confirm("WARNING: This sends a REAL PERMANENT Kick ban to " + targetName + " in " + channelName + ". This is not a timeout and may require a separate unban action. Continue?")) return;
          const typed = prompt('Type exactly "' + confirmationText + '" to confirm the permanent ban:');
          if (typed === null) return;
          ban.disabled = true;
          status.textContent = "Sending permanent-ban request to Kick…";
          try {
            const result = await fetch("/api/moderation/ban", {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                broadcasterUserId: event.broadcaster_user_id,
                targetUserId: event.sender_user_id,
                username: event.sender_username || "",
                confirmation: typed,
                reason: "Manual dashboard permanent ban"
              })
            });
            const body = await result.json();
            if (result.status === 401) { showLogin(); throw new Error(body.error || "Please reconnect Kick."); }
            if (!result.ok) throw new Error(body.error || "Kick rejected the permanent ban.");
            status.textContent = "Kick accepted the permanent ban for " + body.target + " in @" + body.channel + ".";
            ban.textContent = "Ban sent";
          } catch (error) {
            status.textContent = error.message;
            ban.disabled = false;
          }
        });
        item.append(ban);
      }
      list.append(item);
    }
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

async function loadProtectedUsers() {
  const status = document.querySelector("#protected-users-status");
  const list = document.querySelector("#protected-users-list");
  try {
    const response = await fetch("/api/protected-users", { cache: "no-store" });
    const data = await response.json();
    if (response.status === 401) { showLogin(); return; }
    if (!response.ok) throw new Error(data.error || "Could not load protected users.");
    list.replaceChildren();
    const users = data.users || [];
    status.textContent = users.length ? users.length + " protected user(s)." : "No protected users added yet.";
    for (const user of users) {
      const item = document.createElement("div");
      item.className = "channel-item";
      const name = document.createElement("strong");
      name.textContent = "@" + user.username;
      const note = document.createElement("span");
      note.textContent = "Protected from manual and automatic moderation";
      const remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = "Remove protection";
      remove.addEventListener("click", async () => {
        if (!confirm("Remove protection for @" + user.username + "?")) return;
        remove.disabled = true;
        try {
          const result = await fetch("/api/protected-users/" + user.id, { method: "DELETE" });
          const body = await result.json();
          if (!result.ok) throw new Error(body.error || "Could not remove protection.");
          await loadProtectedUsers();
        } catch (error) { status.textContent = error.message; remove.disabled = false; }
      });
      item.append(name, note, remove);
      list.append(item);
    }
  } catch (error) { status.textContent = error.message; }
}
document.querySelector("#add-protected-user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.querySelector("#protected-user-input");
  const button = document.querySelector("#add-protected-user-button");
  const status = document.querySelector("#protected-users-status");
  button.disabled = true;
  status.textContent = "Adding protected user…";
  try {
    const response = await fetch("/api/protected-users", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: input.value })
    });
    const data = await response.json();
    if (response.status === 401) { showLogin(); throw new Error("Please log in again."); }
    if (!response.ok) throw new Error(data.error || "Could not protect user.");
    input.value = "";
    await loadProtectedUsers();
  } catch (error) { status.textContent = error.message; }
  finally { button.disabled = false; }
});

async function loadBannedWords() {
  const status = document.querySelector("#banned-words-status");
  const list = document.querySelector("#banned-words-list");
  try {
    const response = await fetch("/api/banned-words", { cache: "no-store" });
    const data = await response.json();
    if (response.status === 401) { showLogin(); return; }
    if (!response.ok) throw new Error(data.error || "Could not load banned words.");
    list.replaceChildren();
    const words = data.words || [];
    status.textContent = words.length ? words.length + " banned term(s) saved. Enforcement is still OFF." : "No banned words or phrases added yet.";
    for (const word of words) {
      const item = document.createElement("div");
      item.className = "channel-item";
      const term = document.createElement("strong");
      term.textContent = word.term;
      const note = document.createElement("span");
      note.textContent = "Saved · permanent-ban rule not active";
      const remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = "Remove";
      remove.addEventListener("click", async () => {
        if (!confirm('Remove "' + word.term + '" from the banned list?')) return;
        remove.disabled = true;
        try {
          const result = await fetch("/api/banned-words/" + word.id, { method: "DELETE" });
          const body = await result.json();
          if (!result.ok) throw new Error(body.error || "Could not remove term.");
          await loadBannedWords();
        } catch (error) {
          status.textContent = error.message;
          remove.disabled = false;
        }
      });
      item.append(term, note, remove);
      list.append(item);
    }
  } catch (error) {
    status.textContent = error.message;
  }
}
document.querySelector("#add-banned-word-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.querySelector("#banned-word-input");
  const button = document.querySelector("#add-banned-word-button");
  const status = document.querySelector("#banned-words-status");
  button.disabled = true;
  status.textContent = "Saving term…";
  try {
    const response = await fetch("/api/banned-words", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ term: input.value })
    });
    const data = await response.json();
    if (response.status === 401) { showLogin(); throw new Error("Please log in again."); }
    if (!response.ok) throw new Error(data.error || "Could not save term.");
    input.value = "";
    await loadBannedWords();
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

const originalLoadSettingsForChannels = loadSpamSettings;
loadSpamSettings = async function() { await originalLoadSettingsForChannels(); await loadChannels(); };
const originalCheckHealthWithProtectedUsers = checkHealth;
checkHealth = async function() {
  await originalCheckHealthWithProtectedUsers();
  if (!dashboard.hidden) await loadProtectedUsers();
};
const originalCheckHealth = checkHealth;
checkHealth = async function() {
  await originalCheckHealth();
  if (!dashboard.hidden) await loadSpamSettings();
};
checkHealth();
// Cloudflare deployment test

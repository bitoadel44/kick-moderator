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
    timeoutSeconds: Number(document.querySelector("#spam-timeout").value)
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
      ? `Saved: ${result.repeatCount} repeats in ${result.windowSeconds}s → ${result.timeoutSeconds}s timeout. Rule enabled.`
      : `Saved: ${result.repeatCount} repeats in ${result.windowSeconds}s → ${result.timeoutSeconds}s timeout. Rule off.`;
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
const originalCheckHealth = checkHealth;
checkHealth = async function() {
  await originalCheckHealth();
  if (!dashboard.hidden) await loadSpamSettings();
};
checkHealth();
// Cloudflare deployment test

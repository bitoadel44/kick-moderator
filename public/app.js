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
checkHealth();
// Cloudflare deployment test

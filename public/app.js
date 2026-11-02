const connectButton = document.querySelector("#connect");
const connectionStatus = document.querySelector("#connection-status");
async function checkHealth() {
  const title = document.querySelector("#db-status");
  const detail = document.querySelector("#health-detail");
  try {
    const response = await fetch("/api/health");
    const data = await response.json();
    title.textContent = data.ok ? "Server online" : "Server issue";
    detail.textContent = data.databaseConfigured ? "Worker and D1 database detected." : "Database binding needs setup.";
    if (!data.kickCredentialsConfigured) {
      connectionStatus.textContent = "Kick credentials are missing from Worker settings.";
      connectButton.disabled = true;
    }
    const connection = await fetch("/api/connection").then(r => r.json());
    if (connection.connected) {
      connectionStatus.textContent = "Kick account connected. Granted scopes: " + (connection.scope || "not reported");
      connectButton.textContent = "Reconnect Kick";
    } else if (data.kickCredentialsConfigured) {
      connectionStatus.textContent = "Not connected to Kick yet.";
    }
  } catch {
    title.textContent = "Not deployed";
    detail.textContent = "Deploy the Worker to run the connection check.";
    connectionStatus.textContent = "Unable to check the server.";
  }
}
connectButton.addEventListener("click", () => {
  connectButton.disabled = true;
  connectionStatus.textContent = "Redirecting to Kick…";
  window.location.assign("/api/auth/start");
});
checkHealth();

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      return json({
        ok: true,
        app: env.APP_NAME || "K_Botros Kick Moderator",
        databaseConfigured: Boolean(env.DB),
      });
    }

    if (url.pathname.startsWith("/api/")) {
      return json({ error: "Not implemented yet" }, 501);
    }

    return env.ASSETS.fetch(request);
  },
};

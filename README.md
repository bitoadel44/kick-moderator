# K_Botros Kick Moderator

A lightweight, cloud-hosted moderation dashboard for a Kick channel.

## Architecture

- Cloudflare Worker: public HTTPS webhook endpoint and API backend.
- Cloudflare D1: persistent settings, moderation rules, chat log and audit history.
- Cloudflare Pages/Worker assets: dashboard UI.
- Kick Public API: OAuth, event subscriptions, chat message deletion, bans/timeouts and chat replies.

Kick chat events are delivered through Kick's signed webhook Events API. The application must verify every webhook signature using Kick's current public key before trusting an event.

## Planned features

- Connect the broadcaster's Kick account with OAuth.
- Receive and display live chat messages.
- Configurable moderation rules (spam, repeated messages, blocked words and links).
- Manual delete, timeout, ban and unban controls.
- Moderator/allowlist support and an audit log.
- Safe mode: rules begin in log-only mode; enforcement must be explicitly enabled.

## Free hosting

The initial deployment target is Cloudflare's free tier. Free-tier quotas and service terms can change. This is best-effort free hosting, not a contractual 24/7 uptime guarantee. Review Cloudflare's current limits before deployment.

## Security

- Never commit OAuth client secrets, access/refresh tokens, signing keys, or dashboard passwords.
- Store secrets as Cloudflare Worker secrets, not in source files.
- Verify Kick webhook signatures and timestamps.
- Require authenticated dashboard sessions and protect state-changing requests against CSRF.
- Keep automatic enforcement disabled until the owner tests the rules.

## Development status

Scaffold planned. No credentials or Kick account data are stored in this repository yet.

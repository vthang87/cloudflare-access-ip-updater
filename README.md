# Cloudflare Access Dynamic IP Updater (Go + Docker)

Keeps one **dedicated Cloudflare Access application Bypass policy** synchronized to the host network's current public IPv4. Does not expose a port or require a database.

## Requirements

- Cloudflare Zero Trust Access application protected by an existing Access policy.
- A **dedicated** Bypass policy with **exactly one** `Include → IP ranges` selector (initially your current public IP `/32`). Do not share this policy with unrelated conditions.
- API token with permission to read/edit Access applications and policies for the account (use the minimum available scope).
- Docker Compose on a machine **inside the LAN**, using its normal outbound WAN connection (not a VPN/proxy).

## Run

```sh
cp .env.example .env
# Edit .env; keep DRY_RUN=true for the first run
chmod 600 .env
docker compose up -d --build
docker compose logs -f
```

To use the prebuilt image (`linux/amd64`, `linux/arm64`) published by GitHub Actions instead of building locally:

```sh
docker compose pull && docker compose up -d
```

Check that logs show the detected IP and intended policy update. Then change `DRY_RUN=false` and run:

```sh
docker compose up -d --force-recreate
```

## Environment

| Variable | Meaning |
| --- | --- |
| `CF_API_TOKEN` | Cloudflare API token |
| `CF_ACCOUNT_ID` | Cloudflare account ID |
| `CF_APP_ID` | Access application ID. **Optional**: leave empty when `CF_POLICY_ID` is a reusable (account-level) policy |
| `CF_POLICY_ID` | Application policy ID, or reusable policy ID when `CF_APP_ID` is empty |
| `CHECK_INTERVAL` | Interval, minimum `1m` (default `5m`) |
| `IP_CHECK_URL` | Plain-text public IPv4 endpoint (default `https://api.ipify.org`) |
| `DRY_RUN` | `true` prevents updates |

## Behavior / safeguards

- Syncs at startup and periodically thereafter.
- Reads policy each cycle and updates only if the public IPv4 changed.
- Refuses to change a policy unless its decision is `bypass` and it has exactly one IP Include selector.
- Keeps the policy's other supported writable fields when issuing the PUT request.
- Logs errors without exposing the API token; next cycle retries.
- **IP-based bypass trusts every client sharing that public egress IP.** Keep application-level authentication in place.
- A public IP change can temporarily interrupt access until the next successful sync.
- A reusable policy can be attached to several applications; updating it updates all of them.
- Does not support IPv6 or IP lists in this MVP.
- Verify API compatibility and permission scopes in your Cloudflare account before production use.

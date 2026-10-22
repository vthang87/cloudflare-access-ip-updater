# Cloudflare Access Dynamic IP Updater (Go + Docker)

Keeps one **dedicated Cloudflare Access Bypass policy** synchronized to the host network's current public **IPv4 and IPv6**. Does not expose a port or require a database.

## Requirements

- Cloudflare Zero Trust Access application protected by an existing Access policy.
- A **dedicated** Bypass policy whose Include rules are only IP ranges (one IPv4 `/32` and optionally one IPv6 `/128`). Do not share this policy with email/group selectors.
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
| `IP_CHECK_URL` | Cloudflare `cdn-cgi/trace` URL (default `https://cloudflare.com/cdn-cgi/trace`); fetched once over IPv4 and once over IPv6 |
| `DRY_RUN` | `true` prevents updates |

## Finding the values in Cloudflare

### `CF_ACCOUNT_ID`

Open [dash.cloudflare.com](https://dash.cloudflare.com) and select the account. The 32-character hex string right after the domain in the URL (`https://dash.cloudflare.com/<ACCOUNT_ID>/...`) is the account ID. It is also shown in the **API** section on the right side of any zone's **Overview** page.

### `CF_API_TOKEN`

1. **My Profile → API Tokens → Create Token → Create Custom Token**.
2. Permissions: `Account` → `Access: Apps and Policies` → `Edit`.
3. Account Resources: `Include` → your account.
4. Do **not** set Client IP Address Filtering — the host's IP is exactly what changes.
5. Create the token and copy it (it is shown only once).

### Bypass policy

Create a dedicated policy in the [Zero Trust dashboard](https://one.dash.cloudflare.com) with **Action: Bypass** and Include rules that are only **IP ranges** (start with your current IPv4 `/32`; the updater will add/update IPv6 `/128` as well). Choose one of:

- **Reusable policy (recommended)**: **Access → Policies → Add a policy**, then attach it to each application under the application's **Policies** tab. Set `CF_POLICY_ID` and leave `CF_APP_ID` empty.
- **Application policy**: created inside one application's **Policies** tab. Set both `CF_APP_ID` and `CF_POLICY_ID`.

### `CF_APP_ID` and `CF_POLICY_ID`

The IDs are UUIDs and usually appear in the browser URL when you open the application or policy for editing. Note that the application's **AUD tag** is *not* the application ID.

The most reliable way is to list them with the API, using the token and account ID from above (requires `jq`):

```sh
export CF_API_TOKEN=... CF_ACCOUNT_ID=...
api() { curl -s -H "Authorization: Bearer $CF_API_TOKEN" "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID$1"; }

# Reusable policies -> CF_POLICY_ID
api /access/policies | jq -r '.result[] | [.id, .decision, .name] | @tsv'

# Applications -> CF_APP_ID
api /access/apps | jq -r '.result[] | [.id, .name, .domain] | @tsv'

# Policies of one application -> CF_POLICY_ID
api /access/apps/<CF_APP_ID>/policies | jq -r '.result[] | [.id, .decision, .name] | @tsv'
```

Pick the row whose decision is `bypass`. Running the updater with `DRY_RUN=true` confirms the IDs are correct: it logs `IP unchanged` or `IP changed` instead of an error.

## Behavior / safeguards

- Syncs at startup and periodically thereafter.
- Detects public IPv4 and IPv6 via Cloudflare `cdn-cgi/trace` (`tcp4` / `tcp6`).
- Reads policy each cycle and updates only if the Include IP set changed.
- Refuses to change a policy unless its decision is `bypass` and every Include selector is a single-host IP (`/32` or `/128`), max two.
- Keeps the policy's other supported writable fields when issuing the PUT request.
- Logs errors without exposing the API token; next cycle retries.
- **IP-based bypass trusts every client sharing that public egress IP.** Keep application-level authentication in place.
- A public IP change can temporarily interrupt access until the next successful sync.
- Host (and Docker) must have working IPv6 outbound, or IPv6 detection fails and the cycle errors without changing the policy.
- A reusable policy can be attached to several applications; updating it updates all of them.
- Verify API compatibility and permission scopes in your Cloudflare account before production use.

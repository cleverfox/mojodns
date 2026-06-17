# Issuing Let's Encrypt certificates with acme.sh and mojodns

mojodns exposes a small **PowerDNS-compatible API** so [acme.sh](https://github.com/acmesh-official/acme.sh)
can solve **DNS-01** challenges using its stock `dns_pdns` plugin — no custom
plugin, no sharing your panel password. This means you can issue certificates for
any name in a zone you manage, **including wildcards** (`*.example.com`), fully
automated and auto-renewing.

## How it works

- acme.sh's `dns_pdns` plugin talks to what it thinks is a PowerDNS server; mojodns
  emulates exactly the endpoints it uses (`/api/v1/servers/<id>/zones…`).
- Requests are authenticated with a **mojodns API token** sent as the
  `X-API-Key` header (acme.sh does this for you via `PDNS_Token`).
- The token is **scoped**: it can only touch zones you own or have edit access to,
  and it may only create/remove **TXT** records (the DNS-01 challenge record) —
  it can't change anything else.
- mojodns sends NOTIFY to the public secondaries on every change, so challenge
  records appear on the public nameservers within a couple of seconds.

## 1. Prerequisites

- **acme.sh** installed — <https://github.com/acmesh-official/acme.sh>:
  ```sh
  curl https://get.acme.sh | sh -s email=you@example.com
  # then restart your shell, or: source ~/.bashrc
  ```
- The **zone** you want a certificate for is already managed in mojodns (e.g.
  `example.com`), and its public nameservers are live.
- An **API token** (next step).

## 2. Create an API token

Tokens are self-service in the panel:

1. Log in to the panel and open **Account** (top-right nav).
2. Under **API tokens**, enter a name (e.g. `acme-web01`) and pick an **expiry**.
   - For unattended renewals choose a **long** interval (e.g. **2–5 years**) so the
     cron renewal keeps working — an expired token makes renewals fail. Set a
     reminder to rotate it before it expires.
3. Click **create token**. The secret is shown **once** — copy it now; it's stored
   hashed and can't be displayed again. If you lose it, just create a new one and
   revoke the old.

The token acts on your behalf and only reaches your zones.

## 3. Configure acme.sh

Point the `dns_pdns` plugin at your panel. Replace the URL with your panel's
address and paste the token you just created:

```sh
export PDNS_Url="https://mojodns.aksinet.net"   # your panel URL, no trailing path
export PDNS_ServerId="localhost"
export PDNS_Token="<the token from step 2>"
export PDNS_Ttl=60
```

- `PDNS_Url` is just the scheme + host (acme.sh appends `/api/v1/servers/...`).
- `PDNS_ServerId` is always `localhost`.
- `PDNS_Ttl=60` keeps the challenge TXT short-lived.

acme.sh **saves these values** after the first successful issue (in
`~/.acme.sh/account.conf`), so renewals reuse them automatically — you only export
them once.

## 4. Issue a certificate

Single name:

```sh
acme.sh --issue --dns dns_pdns -d example.com
```

With a wildcard (covers `example.com` and all first-level subdomains):

```sh
acme.sh --issue --dns dns_pdns -d example.com -d '*.example.com'
```

acme.sh will: ask mojodns to add the `_acme-challenge` TXT record(s), wait for
Let's Encrypt to validate, then remove them. Propagation is fast, so the default
wait is normally enough; on a slow resolver path you can add `--dnssleep 30`.

## 5. Install the certificate

Tell acme.sh where to place the files and how to reload your service. Example for
nginx:

```sh
acme.sh --install-cert -d example.com \
  --key-file       /etc/nginx/ssl/example.com.key \
  --fullchain-file /etc/nginx/ssl/example.com.fullchain.pem \
  --reloadcmd      "systemctl reload nginx"
```

For a wildcard, install under the base name (`-d example.com`).

## 6. Renewal

acme.sh installs a daily cron job and renews certificates ~30 days before expiry,
reusing the saved `PDNS_*` values and your install settings. Nothing else to do —
**except** keep the API token valid:

- If the token **expires** or is **revoked**, renewals fail with `token expired` /
  `invalid token`. Create a fresh token on **Account**, then update acme.sh:
  ```sh
  export PDNS_Token="<new token>"
  acme.sh --renew -d example.com --force   # re-saves the new token
  ```
- Force a test renewal any time: `acme.sh --renew -d example.com --force`.

## Troubleshooting

Run with `--debug 2` to see the API calls:

```sh
acme.sh --issue --dns dns_pdns -d example.com --debug 2
```

| Symptom | Cause / fix |
|---|---|
| `401` / `invalid token` | Wrong/empty `PDNS_Token`. Re-copy it (it's shown only at creation) or make a new one on **Account**. |
| `401` / `token expired` | The token's expiry passed — create a new one and re-run with `--force` (see Renewal). |
| Zone "not found" / 404 on PATCH | The token's user doesn't own/edit that zone in mojodns, or the base domain isn't a zone here. Check the zone is yours in the panel. |
| Challenge fails to validate | Confirm the zone's public nameservers are serving (panel → zone → **check DNS servers**). Try `--dnssleep 30`. |
| Wildcard not trusted | You must issue with `-d '*.example.com'` (quote it so the shell doesn't glob). |

## Security notes

- The token is a **credential** — treat it like a password. Don't commit it; it
  lives in acme.sh's `account.conf` on the host that renews.
- Prefer the `X-API-Key` header (acme.sh uses it automatically); avoid putting
  tokens in URLs.
- Scope is enforced server-side: a token can only add/remove **TXT** records in the
  **zones its owner manages**. Use a dedicated token per host so you can revoke one
  without affecting the others.
- Revoke unused tokens on **Account** at any time.

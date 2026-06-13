# Installing mojodns on a fresh Ubuntu server

This guide installs the full mojodns stack (web panel + PowerDNS hidden
primary + PostgreSQL) behind **nginx with HTTPS** from a free Let's Encrypt
certificate managed by **acme.sh**. It is written from a real deployment on
Ubuntu 24.04 and includes the two gotchas that deployment hit.

Worked example used throughout: domain **`mojodns.example.com`**, server IP
**`203.0.113.10`**. Substitute your own. Commands assume a non-root user with
passwordless `sudo` (replace `sudo` semantics as needed).

---

## 0. Prerequisites

| Requirement | Notes |
|---|---|
| Ubuntu 22.04 / 24.04, x86_64 | Other Debian-family distros work with minor changes |
| ≥ 1 GB RAM | The reference host has 948 MB + 1.9 GB swap and builds fine; add swap if you have none (see 1a) |
| ≥ 5 GB free disk | Images + Postgres data |
| A DNS **A record** for your panel hostname → the server IP | Required for the Let's Encrypt HTTP‑01 challenge. Verify before you start: `dig +short mojodns.example.com` must return the server's IP |
| Ports **80** and **443** reachable from the internet | ACME challenge + the panel |
| Port **53** reachable from your future NSD slaves | Only needed when you add public secondaries; the panel works without it |
| `sudo`, `curl`, `rsync`, `git` | `curl`/`rsync`/`git` are usually preinstalled |

What you'll end up with:

```
internet ──443/80──► nginx (TLS) ──► 127.0.0.1:8000  web panel (FastAPI)
                                          │ REST
                                          ▼
                                       pdns ──► postgres   (docker compose)
internet ──53──► pdns (hidden primary, optional until you add NSD slaves)
```

---

## 1. System preparation

### 1a. Swap (skip if you already have swap or ≥ 2 GB RAM)

```sh
free -h | grep -i swap          # check first
sudo fallocate -l 2G /swap.img && sudo chmod 600 /swap.img
sudo mkswap /swap.img && sudo swapon /swap.img
echo '/swap.img none swap sw 0 0' | sudo tee -a /etc/fstab
```

### 1b. Free port 53 from systemd-resolved  ⚠️ critical on Ubuntu

A fresh Ubuntu runs `systemd-resolved`, which **listens on 127.0.0.53:53**.
PowerDNS wants to bind `0.0.0.0:53`, which overlaps. Disable the resolved
*stub listener* (the rest of resolved keeps working) and repoint
`/etc/resolv.conf` at the real upstreams:

```sh
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNS=1.1.1.1 8.8.8.8\nDNSStubListener=no\n' \
  | sudo tee /etc/systemd/resolved.conf.d/mojodns.conf
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

Verify port 53 is now free **and** name resolution still works:

```sh
sudo ss -tulpnH | grep ':53 ' || echo 'PORT 53 FREE'
getent hosts github.com          # must still resolve
```

> If you are **not** going to run DNS on this host (panel-only, talking to a
> remote PowerDNS), skip 1b and set `DNS_PORT` to a high port in step 3.

---

## 2. Install Docker Engine + Compose

From Docker's official APT repository (the Ubuntu `docker.io` package is
older and lacks the compose plugin):

```sh
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update -qq
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
                        docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"        # optional: run docker without sudo (re-login to apply)
sudo systemctl enable --now docker
docker --version && docker compose version
```

> The group change only takes effect in a **new** login session. Until you
> re-login, use `sudo docker …` (this guide does).

---

## 3. Get the code and configure secrets

Copy the project to `/opt/mojodns` (rsync from your workstation, or
`git clone`):

```sh
sudo mkdir -p /opt/mojodns && sudo chown "$USER:$USER" /opt/mojodns
# from your workstation:
rsync -az --exclude '.venv' --exclude '__pycache__' --exclude '.git' \
      --exclude '.env' mojodns-py/ SERVER:/opt/mojodns/
```

Generate strong secrets and write `/opt/mojodns/.env`:

```sh
cd /opt/mojodns
cat > .env <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 16)
PDNS_API_KEY=$(openssl rand -hex 24)
SESSION_SECRET=$(openssl rand -hex 32)
BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-16)

# DNS defaults for new zones — adjust to your nameservers
CATALOG_ZONE=catalog.example.com.
DEFAULT_SOA_NS=ns1.example.com.
DEFAULT_SOA_MAIL=hostmaster.example.com.
DEFAULT_NAMESERVERS=ns1.example.com.,ns2.example.com.

# slaves: leave empty until you have public NSD secondaries
ALSO_NOTIFY_IPS=
ALLOW_AXFR_IPS=

# bind the web app to localhost only — nginx is the only front door
WEB_PORT=127.0.0.1:8000
DNS_PORT=53

VERIFY_RESOLVERS=1.1.1.1,8.8.8.8
VERIFY_INTERVAL_HOURS=24
EOF
chmod 600 .env
```

Keep `BOOTSTRAP_ADMIN_PASSWORD` — it's the first login. `WEB_PORT=127.0.0.1:8000`
is important: it stops Docker from publishing the panel on the public
interface, so only nginx can reach it.

---

## 4. Build and start the stack

```sh
cd /opt/mojodns
sudo docker compose build          # ~2-3 min; builds the Python web image
sudo docker compose up -d
sudo docker compose ps             # wait until pdns + postgres are "healthy"
```

The web container creates the `admin` user (password from
`BOOTSTRAP_ADMIN_PASSWORD`) and the catalog zone on first start.

---

## 5. Verify the stack (before adding nginx)

```sh
# panel responds on localhost (303 redirect to /login is correct)
curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}\n' http://127.0.0.1:8000/
# DNS answers on port 53
dig @127.0.0.1 "$(grep ^CATALOG_ZONE= .env | cut -d= -f2)" SOA +short
# admin was created
sudo docker compose logs web | grep -i bootstrap
```

---

## 6. nginx + HTTPS (acme.sh / Let's Encrypt)

### 6a. Install nginx with an HTTP-only config (for the ACME challenge)

```sh
sudo apt-get install -y nginx
sudo mkdir -p /var/www/acme
sudo rm -f /etc/nginx/sites-enabled/default

DOMAIN=mojodns.example.com
sudo tee /etc/nginx/sites-available/mojodns >/dev/null <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
NGINX
sudo ln -sf /etc/nginx/sites-available/mojodns /etc/nginx/sites-enabled/mojodns
sudo nginx -t && sudo systemctl reload nginx
curl -s -o /dev/null -w '%{http_code}\n' http://$DOMAIN/   # 303 = panel reachable over HTTP
```

### 6b. Install acme.sh and issue the certificate

```sh
curl -s https://get.acme.sh | sudo sh -s email=hostmaster@example.com
sudo /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
sudo /root/.acme.sh/acme.sh --issue -d $DOMAIN -w /var/www/acme
```

### 6c. Install the cert and switch nginx to HTTPS

```sh
sudo mkdir -p /etc/nginx/ssl
sudo /root/.acme.sh/acme.sh --install-cert -d $DOMAIN --ecc \
  --key-file       /etc/nginx/ssl/mojodns.key \
  --fullchain-file /etc/nginx/ssl/mojodns.fullchain.pem \
  --reloadcmd      "systemctl reload nginx"

sudo tee /etc/nginx/sites-available/mojodns >/dev/null <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    ssl_certificate     /etc/nginx/ssl/mojodns.fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/mojodns.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 10m;          # for zone-file imports

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
NGINX
sudo nginx -t && sudo systemctl reload nginx
```

> ⚠️ **nginx version gotcha.** The standalone `http2 on;` directive only
> exists in nginx ≥ 1.25.1. Ubuntu 24.04 ships **1.24**, which needs the old
> form `listen 443 ssl http2;` (used above). If `nginx -t` says
> *unknown directive "http2"*, this is why.

---

## 7. Verify HTTPS

```sh
curl -sI http://$DOMAIN/  | grep -i location          # 301 -> https://
curl -s -o /dev/null -w '%{http_code}\n' https://$DOMAIN/login
echo | openssl s_client -connect $DOMAIN:443 -servername $DOMAIN 2>/dev/null \
  | openssl x509 -noout -issuer -dates
```

Then open **https://mojodns.example.com/** and log in as `admin` with the
`BOOTSTRAP_ADMIN_PASSWORD` from `.env`.

---

## 8. Post-install hardening

1. **Change the admin password** in the panel (Users → admin), or rotate
   `BOOTSTRAP_ADMIN_PASSWORD` is irrelevant after first boot.
2. **Firewall.** Allow 22/80/443 to the world; restrict **53** to your NSD
   slave IPs once you know them (until then pdns answers publicly but
   harmlessly). Example with `ufw`:
   ```sh
   sudo ufw allow 22,80,443/tcp
   # sudo ufw allow from <SLAVE_IP> to any port 53        # per slave, tcp+udp
   sudo ufw enable
   ```
   Take care not to lock yourself out of SSH.
3. **TSIG for zone transfers** (recommended once you add slaves): generate a
   key and enable signed transfers —
   ```sh
   sudo docker compose exec pdns pdnsutil --config-dir=/tmp/pdns \
        generate-tsig-key mojodns-xfr hmac-sha256
   # put TSIG_KEY/TSIG_SECRET/TSIG_ALGO in .env, set ALLOW_AXFR_IPS="", then:
   sudo docker compose up -d
   ```
   See `nsd-slave/README.md` for the slave side.
4. **Add public NSD secondaries** — fill `ALSO_NOTIFY_IPS` / `ALLOW_AXFR_IPS`
   in `.env`, `sudo docker compose up -d pdns`, and configure each slave
   (catalog consumer on NSD ≥ 4.9, or `nsd-catalog-sync.sh` for older NSD).

---

## 9. Operations

**Certificate renewal** is automatic — acme.sh installs a daily root cron
that renews ~30 days before expiry and runs the `--reloadcmd`. Force a dry
run with `sudo /root/.acme.sh/acme.sh --renew -d mojodns.example.com --ecc --force`.

**Update the app** (after pulling new code into `/opt/mojodns`):
```sh
cd /opt/mojodns && sudo docker compose up -d --build web
```

**Backups** — everything important is in two places:
```sh
# the app + DNS database (PostgreSQL volume)
sudo docker compose exec -T postgres pg_dump -U dns dns | gzip > mojodns-$(date +%F).sql.gz
# and /opt/mojodns/.env  (secrets) — store securely
```

**Logs / status:**
```sh
sudo docker compose ps
sudo docker compose logs -f web
```

**Restart everything / after reboot:** containers are `restart: unless-stopped`
and Docker is enabled at boot, so the stack comes back on its own. Manual:
`cd /opt/mojodns && sudo docker compose up -d`.

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `docker compose up` fails to bind `:53` | `systemd-resolved` stub still on 53 — do step **1b**. With rootless Docker you also can't bind <1024; use a rootful daemon or set `DNS_PORT` high. |
| `nginx -t`: *unknown directive "http2"* | nginx < 1.25.1 — use `listen 443 ssl http2;`, not `http2 on;` (step 6c). |
| acme.sh: challenge fails | The A record must point at this host and port 80 must be open; re-run after fixing. Check `curl http://DOMAIN/.well-known/acme-challenge/test` after `echo test | sudo tee /var/www/acme/.well-known/acme-challenge/test`. |
| Panel reachable on `http://IP:8000` from outside | `WEB_PORT` not set to `127.0.0.1:8000` — fix `.env`, `docker compose up -d`. |
| Login works on HTTP but loops on HTTPS | nginx must pass `X-Forwarded-Proto $scheme` (included above); the app trusts it via uvicorn `--proxy-headers`. |
| OOM during `docker compose build` | Add swap (step 1a). |

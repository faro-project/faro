# Self-hosting Faro

**Audience:** the person who runs a Faro instance for a church, a college, a small group or themselves. You don't need to be a programmer. You do need to be comfortable copying commands into a terminal on a server (over SSH) and editing a text file.

> **Status: pre-alpha. Read this first.**
>
> - The server (`faro-server`) runs and its API works. Its web app has the **setup page**, **sign-in** by emailed link, the **admin console** (overview, inviting members, settings, email test), and the **member and ally pages**: members set up their keys, add and approve computers, invite and approve allies and see their own activity; allies accept invitations and read the alerts and reports of the people they support. There is **no released desktop app** for members yet, only development builds of the macOS client, so members have nothing official to enroll their computers with. This guide is for pilot instances and testers.
> - **There are no releases yet.** You can build the image yourself from the source code (one command; it takes a while the first time), or use the development image `ghcr.io/faro-project/faro-server:main` that CI builds from the latest code for amd64 and arm64 (see [Path B](#4-path-b-a-raspberry-pi)).
> - CI builds the container image, but has **not yet tested a running instance inside Docker**. The commands in this guide were checked against the real `faro-server` binary.
> - **The beta supports SQLite only.** Use the built-in SQLite database, which is the right choice for almost everyone anyway. `faro-server` can also run on Postgres (`FARO_DATABASE_URL=postgres://…`), but that is **experimental and not supported in this release**: nothing tests it, and `faro-server doctor` and the startup log warn about it.
> - The **update mirror** is built, and the macOS client installs updates from it, but the Faro project hasn't published a signed release or its root of trust yet, so there is nothing to mirror. See [Updates for members' computers](#updates-for-members-computers).
> - Not built yet: passkey sign-in (you sign in with email links for now), Web Push notifications (email only), and S3 storage for attachments (local disk only).

## Contents

1. [What you need](#1-what-you-need)
2. [Choose how to host it](#2-choose-how-to-host-it)
3. [Path A: a VPS with Docker Compose](#3-path-a-a-vps-with-docker-compose)
4. [Path B: a Raspberry Pi](#4-path-b-a-raspberry-pi)
5. [Path C: a home server without a public address](#5-path-c-a-home-server-without-a-public-address)
6. [First run: create the admin account](#6-first-run-create-the-admin-account)
7. [Email (SMTP)](#7-email-smtp)
8. [Checking your instance: `faro-server doctor`](#8-checking-your-instance-faro-server-doctor)
9. [Backups and restore](#9-backups-and-restore)
10. [Upgrading](#10-upgrading)
11. [What you as the operator can and cannot see](#11-what-you-as-the-operator-can-and-cannot-see)
12. [Without Docker: the binary and systemd](#12-without-docker-the-binary-and-systemd)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. What you need

- **A computer that is always on and reachable from the internet.** Members' computers report to the instance from wherever they are (home, work, travelling), so an instance that only works on your own Wi-Fi isn't supported. Any of these works:

  | Instance size | Active computers | Hardware | Disk (30-day retention) |
  |---|---|---|---|
  | Individual or small group | up to 50 | Raspberry Pi 4/5, or a 1 vCPU / 1 GB VPS | about 1 GB |
  | Church | up to 1,000 | 2 vCPU / 2 GB | about 10 GB |
  | College | up to 10,000 | 4 vCPU / 8 GB | about 100 GB |

  These are estimates. Building the software needs more memory than running it (see the note on swap in Path A).
- **A web address (domain name)** such as `faro.yourchurch.org`. A subdomain of a domain you already own is ideal. With Tailscale Funnel (Path C) you can use a free `….ts.net` name instead.

  **Pick a name you'll keep.** Members' computers remember the instance's address and identity when they enroll; changing the address later means everyone re-enrolls.
- **An email account that can send mail over SMTP** (Google Workspace, Microsoft 365, Mailgun, Amazon SES, your web host's mail, …). Faro sends sign-in links, invitations and alerts by email. See [section 7](#7-email-smtp).
- **About an hour**, most of which is waiting for the first build.

## 2. Choose how to host it

| | Path | Good for | HTTPS by |
|---|---|---|---|
| **A** | [A VPS](#3-path-a-a-vps-with-docker-compose) (rented server, about $5/month) | Most people. Churches. | Faro itself (Let's Encrypt), or Caddy |
| **B** | [A Raspberry Pi](#4-path-b-a-raspberry-pi) at home or in the church office | Individuals, small groups | Faro itself with a router port forward, or Path C |
| **C** | [A home server without a public address](#5-path-c-a-home-server-without-a-public-address) | Homes and offices where you can't open ports | Cloudflare Tunnel or Tailscale Funnel |

All three use Docker Compose and the files in the `deploy/` folder of the Faro source code. If you'd rather not use Docker, see [section 12](#12-without-docker-the-binary-and-systemd).

There are two ways to provide HTTPS, and you choose one in the settings file:

- **Mode A, built-in HTTPS.** Faro gets a free certificate from Let's Encrypt and renews it itself. It needs port 443 on your server reachable from the internet. Nothing else to install.
- **Mode B, behind a proxy or tunnel.** Something else handles HTTPS (Caddy, nginx, Traefik, Cloudflare Tunnel, Tailscale Funnel) and passes requests to Faro. Use this if the machine already runs websites, or for Path C.

---

## 3. Path A: a VPS with Docker Compose

**1. Rent a server.** Any provider works (Hetzner, DigitalOcean, Linode, Vultr, OVH, …). Choose **Ubuntu 24.04 LTS** or **Debian 13**, at least 1 GB of memory, and note its **IP address**.

**2. Point your domain at it.** In your domain provider's DNS settings, add an **A record** for `faro` (or whatever name you chose) with the server's IP address. If the server has an IPv6 address, add an **AAAA record** too. It can take a few minutes to take effect.

**3. Log in to the server** from your computer's terminal (on Windows, use PowerShell):

```sh
ssh root@YOUR.SERVER.IP
```

If your provider gave you a non-root user, log in as that user; the commands below use `sudo` either way.

**4. Install Docker and Git:**

```sh
sudo apt-get update && sudo apt-get install -y git curl
curl -fsSL https://get.docker.com | sudo sh
```

If the server has a firewall enabled (`sudo ufw status` says "active"), open the HTTPS port:

```sh
sudo ufw allow 443/tcp
```

**5. On a server with 2 GB of memory or less, add swap space** so the build doesn't run out of memory (this is only needed for building; skip it if `free -h` already shows swap):

```sh
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

**6. Download Faro:**

```sh
git clone https://github.com/faro-project/faro.git
cd faro/deploy
```

From here on, run commands from this `faro/deploy` folder unless a step says otherwise.

**7. Write your settings.** Copy the example settings file, protect it (it will contain your email password), and edit it:

```sh
cp faro.env.example faro.env
chmod 600 faro.env
nano faro.env
```

Change these lines (in `nano`, save with Ctrl+O, Enter, and exit with Ctrl+X):

- `FARO_PUBLIC_URL`: `https://` plus your domain, for example `https://faro.yourchurch.org`.
- `FARO_INSTANCE_NAME`: the name members will see, for example `Grace Church Faro`.
- `FARO_TLS_ACME_DOMAIN`: your domain again, **without** `https://`, for example `faro.yourchurch.org`.
- `FARO_TLS_ACME_CONTACT`: your email address (Let's Encrypt writes to it if a certificate has trouble renewing).
- The `FARO_SMTP_…` lines: your email provider's details ([section 7](#7-email-smtp)). You can leave them for now and add them later, but sign-in and invitations won't work until you do.

That's mode A (built-in HTTPS), which `docker-compose.yml` is set up for. To use **Caddy** instead (if this server already hosts websites), follow the instructions above the `caddy:` section in `docker-compose.yml`.

**8. Create the backups folder.** Faro runs as an unprivileged user (number 10001) inside its container, so give that user the folder:

```sh
mkdir -p backups && sudo chown 10001:10001 backups
```

**9. Build and start Faro:**

```sh
sudo docker compose up -d --build
```

The first build compiles Faro from source and takes roughly 5 to 30 minutes depending on the server. Later starts take seconds.

**10. Check that it's running:**

```sh
sudo docker compose ps
```

After about a minute the `faro` line should say `(healthy)`. Then, from any computer:

```sh
curl https://faro.yourchurch.org/.well-known/faro
```

You should see a line starting `{"instance_id":"inst_…","name":"Grace Church Faro",…`. The very first request can take a few seconds while the certificate is fetched.

Now go to [section 6, First run](#6-first-run-create-the-admin-account).

---

## 4. Path B: a Raspberry Pi

**What you need:** a Raspberry Pi 4 or 5 with at least 2 GB of memory (4 GB is better for building), the **64-bit** Raspberry Pi OS Lite, and ideally a USB SSD instead of an SD card (SD cards wear out under a database; if you use one, keep good backups).

**Reaching the Pi from the internet.** Choose one:

- **Your router forwards port 443 to the Pi** and your domain points at your home's public IP address. This works if your internet provider gives you a public IP address. If that address changes from time to time, you also need a dynamic-DNS service to keep your domain updated. Then use mode A exactly as in Path A.
- **No port forwarding:** use Cloudflare Tunnel or Tailscale Funnel as described in [Path C](#5-path-c-a-home-server-without-a-public-address). This is usually easier at home.

**Steps.** Log in to the Pi with `ssh`, then follow [Path A](#3-path-a-a-vps-with-docker-compose) from step 4 (install Docker) onward, but in step 9 use the prebuilt image below instead of building. Then you can skip step 5 (swap), which is only needed for building.

**Use the prebuilt image (recommended).** Building on a Pi is slow (it can take an hour), so CI publishes a ready-made arm64 image. In the `faro/deploy` folder, tell Docker Compose to use it, then download and start it:

```sh
echo 'FARO_IMAGE=ghcr.io/faro-project/faro-server:main' >> .env
chmod 600 .env
sudo docker compose pull faro
sudo docker compose up -d
```

Leave out `--build` from now on, because `--build` compiles Faro on the Pi again. `:main` is the latest development code. Once releases exist, use a version tag instead, such as `:0.1.0`.

If `pull` says `unauthorized` or `denied`, the image is private (it is while the Faro repository is private). Create a GitHub personal access token (classic) with only the `read:packages` scope, then log in once on the Pi and pull again:

```sh
sudo docker login ghcr.io -u YOUR-GITHUB-USERNAME
# paste the token when it asks for a password
```

**Or build it yourself on a faster computer.** If you have a faster computer with Docker, you can build the image there and copy it over:

```sh
# On the faster computer, in the faro folder (not faro/deploy):
docker buildx build --platform linux/arm64 -f deploy/Dockerfile -t faro-server:local --load .
docker save faro-server:local | ssh pi@YOUR.PI.ADDRESS 'sudo docker load'
```

Then, on the Pi, start it with `sudo docker compose up -d` (without `--build`).

---

## 5. Path C: a home server without a public address

If you can't open ports on your router (or don't want to), a tunnel service carries traffic from the internet to your server. Both options below are free for this use.

**What a tunnel can see.** With Cloudflare Tunnel, Cloudflare handles HTTPS for you, so Cloudflare can see the same things you as the operator can see ([section 11](#11-what-you-as-the-operator-can-and-cannot-see)): metadata such as who uses the instance and when, but **not** reports, screenshots or alerts, because those are end-to-end encrypted on members' computers. With Tailscale Funnel, HTTPS is handled on your own server; Tailscale relays encrypted traffic.

### Option C1: Cloudflare Tunnel

You need a domain whose DNS is managed by Cloudflare (a free Cloudflare account is enough).

1. Follow [Path A](#3-path-a-a-vps-with-docker-compose) steps 4 to 8 on your home server (skip the firewall and DNS steps; the tunnel needs no open ports).
2. In `faro.env`, switch to mode B: put a `#` in front of the two `FARO_TLS_ACME_…` lines, and remove the `#` in front of `FARO_BEHIND_PROXY=true`.
3. In the [Cloudflare dashboard](https://dash.cloudflare.com), go to **Zero Trust → Networks → Tunnels**, create a tunnel of type **Cloudflared**, and copy the **token** it shows (the long string after `--token` in the install command). You don't need to run Cloudflare's install command.
4. In the tunnel's **Public Hostname** tab, add your hostname (for example `faro.yourchurch.org`), with **Service type** `HTTP` and **URL** `faro:8080`.
5. Save the token next to `docker-compose.yml`:

   ```sh
   echo 'CLOUDFLARE_TUNNEL_TOKEN=PASTE-THE-TOKEN-HERE' > .env
   chmod 600 .env
   ```

6. Edit `docker-compose.yml` (`nano docker-compose.yml`):
   - In the `faro` service, put `#` in front of `- "443:8080"` and remove the `#` in front of `- "127.0.0.1:8080:8080"`.
   - In the `cloudflared:` section, remove the `# ` at the start of each line from `cloudflared:` down to `- faro`, keeping the indentation the same as the `faro:` service.
7. Start it: `sudo docker compose up -d --build`, then check with `curl https://faro.yourchurch.org/.well-known/faro` as in Path A step 10.

Don't put Cloudflare Access, "Under Attack" mode or other browser challenges in front of this hostname: the desktop app can't solve them, and members' computers would appear to go silent.

### Option C2: Tailscale Funnel

Your instance gets an address like `https://homeserver.tail1234.ts.net`, so you don't need your own domain. The name depends on the machine name and your tailnet name; keep both stable.

1. Install Tailscale on the server and sign in:

   ```sh
   curl -fsSL https://tailscale.com/install.sh | sh
   sudo tailscale up
   ```

2. Follow [Path A](#3-path-a-a-vps-with-docker-compose) steps 5 to 8 (skip the DNS and firewall steps).
3. Start the funnel to Faro's local port. The first time, Tailscale prints a link to enable HTTPS and Funnel for your tailnet; open it and approve:

   ```sh
   sudo tailscale funnel --bg 8080
   sudo tailscale funnel status
   ```

   The status shows your public `https://….ts.net` address.
4. In `faro.env`:
   - set `FARO_PUBLIC_URL` to that `https://….ts.net` address;
   - put a `#` in front of the two `FARO_TLS_ACME_…` lines;
   - remove the `#` in front of `FARO_BEHIND_PROXY=true`.
5. In `docker-compose.yml`, in the `faro` service, put `#` in front of `- "443:8080"` and remove the `#` in front of `- "127.0.0.1:8080:8080"`.
6. Start it: `sudo docker compose up -d --build`, then check `curl https://YOUR-NAME.ts.net/.well-known/faro`.

---

## 6. First run: create the admin account

You create the admin account on your instance's setup page, using a one-time token from the server's log.

**1. Find the one-time setup token.** The first time Faro starts, it prints a token in its log:

```sh
sudo docker compose logs faro | grep -A2 'setup token'
```

You'll see something like:

```
faro-1  | One-time setup token (valid 24 hours, single use):
faro-1  |
faro-1  |     xkaJFpo_XSesNsQ-EbUJAz4qhd194Q0EgKUmDT7gGBU
```

If the token is missing (for example because the container was recreated) or more than 24 hours old, make a new one. This cancels any older token:

```sh
sudo docker compose exec faro faro-server init
```

**2. Open the setup page** in your web browser: `https://faro.yourchurch.org/setup` (your instance's address followed by `/setup`). It walks you through three steps:

- **Admin account:** paste the token and enter your email address and name. This creates the admin account and signs this browser in. The token then stops working, and nobody else can claim the instance. The admin account is also a member account, so you can use Faro yourself; being admin gives you no access to anyone else's data.
- **Email:** sends a test message to your address. Set up email first ([section 7](#7-email-smtp)); if the test fails, the page explains the error code. You can skip this and come back.
- **Registration and retention:** who may create an account (invite only, anyone with an address at your domains, or closed) and how many days data is kept. You can keep the defaults.

**3. Use the admin console** at `https://faro.yourchurch.org/admin` (the **Admin** link at the top of every page, once you're signed in as the admin):

- **Overview:** how many people and computers there are, when computers last checked in, storage use and email delivery, plus the notice members see of what you can and cannot see as the operator.
- **People:** invite members by email, and see accounts (names, email addresses, roles, last sign-in and how many computers each has). An invited person accepts by signing in with the invited address. You can also **disable** an account, which stops that person signing in. Faro always emails them and everyone in an accountability partnership with them (their allies, and the members they are an ally for), and their computers keep being monitored. Admins are treated like everyone else: another admin can disable your account, but nobody can disable their own. People can delete their own accounts from Settings. The People page then shows "being deleted" with the date, and while the deletion waits you can't disable or re-enable that account. As the only admin you can't delete your own account.
- **Settings:** registration, retention and the missed check-in grace period.
- **Branding:** your logo and a few things to show or hide (see below).
- **Email:** send yourself a test message.

If you've been signed out (sessions last 30 days), sign in at `/signin`: enter your email address and open the link Faro emails you. Signing in needs working email, so set it up ([section 7](#7-email-smtp)).

### Branding your instance

**Admin → Branding** lets you add your own logo and choose what else to show. Changes apply on the next page load, without a restart, and nobody is notified.

- **Logo.** Upload a PNG, JPEG or WebP file of up to 1 MB and 4096 pixels on each side. SVG is not accepted, because SVG files can contain scripts. Faro makes its own copy as a PNG, at most 512 pixels wide or high, without the file's metadata, and serves it from your instance. It shows in the header and on the sign-in and setup pages: your logo, a thin line, then Faro's logo. It never replaces Faro's logo. Pick a logo that reads well on white: in the dark theme it is shown on a white background. You can replace or remove it at any time.
- **What to show.** Each of these can be switched on or off:
  - your logo;
  - the instance name in the header (on by default; the name itself is set in `faro.toml`);
  - a welcome line on the sign-in page: one line of plain text, up to 200 characters;
  - a support contact in the footer and on the sign-in page: an email address or an `https://` link.

Your text is shown exactly as you type it, as plain text (no HTML or formatting), and always labelled as coming from your instance's admins. It appears only in the header, footer and sign-in page, never in alerts, reports, safety codes or emails. Faro refuses line breaks and invisible or text-direction characters.

The logo and these settings are stored in the database, so backups include them.

**Faro's logo and yours.** Faro's logo comes with the software and is never recoloured or changed (see `assets/brand/README.md`); you may use it to say you run Faro. Your logo is yours: Faro shows it next to its own, re-encoded, never in place of it.

### The same tasks with `curl`

Everything above can also be done with `curl`, for example to script it, or with a build of `faro-server` that has no web app. Run these commands on the server itself (or on any Mac or Linux computer). They talk to your instance's real `https://` address, which also proves HTTPS works.

Steps 2 and 3 create the admin account without the setup page. **If you used the setup page, skip them:** do step 1, sign `curl` in with "Signing `curl` in" (after step 9), and continue at step 4.

**1. Save your instance address and the token** in the terminal, so the commands below can use them (replace both values with yours):

```sh
FARO=https://faro.yourchurch.org
TOKEN=xkaJFpo_XSesNsQ-EbUJAz4qhd194Q0EgKUmDT7gGBU
```

**2. Check that the instance is waiting for setup:**

```sh
curl -s "$FARO/v1/setup"
```

It should answer `{"needs_setup":true}`.

**3. Create the admin account** (use your real email address and name). This also signs you in: `curl` keeps your sign-in in the file `faro-admin.cookies`.

```sh
curl -s -c faro-admin.cookies -X POST "$FARO/v1/setup" \
  -H 'Content-Type: application/json' \
  -d "{\"setup_token\": \"$TOKEN\", \"email\": \"you@yourchurch.org\", \"display_name\": \"Your Name\"}"
```

The answer starts with `{"user":{"id":"usr_…"` and shows `"admin":true`. The token now stops working, and nobody else can claim the instance. The admin account is also a member account, so you can use Faro yourself; being admin gives you no access to anyone else's data.

**4. Check that you're signed in:**

```sh
curl -s -b faro-admin.cookies "$FARO/v1/me"
```

**5. Send yourself a test email** (set up email first, [section 7](#7-email-smtp)):

```sh
curl -s -b faro-admin.cookies -X POST "$FARO/admin/api/smtp-test"
```

`{"ok":true,"error":null,"sent_to":"you@yourchurch.org"}` means the email was handed to your mail provider; check your inbox (and spam folder). The test always goes to your own address. If `ok` is `false`, see the error codes in [section 7](#7-email-smtp).

**6. Look at the instance overview** (counts only; see [section 11](#11-what-you-as-the-operator-can-and-cannot-see)):

```sh
curl -s -b faro-admin.cookies "$FARO/admin/api/overview"
curl -s -b faro-admin.cookies "$FARO/admin/api/users"
```

**7. Change settings (optional).** Registration is invite-only by default. To let anyone with an address at your college sign up, or to shorten how long data is kept:

```sh
curl -s -b faro-admin.cookies -X PATCH "$FARO/admin/api/settings" \
  -H 'Content-Type: application/json' \
  -d '{"registration_mode": "open", "allowed_email_domains": ["college.edu"]}'

curl -s -b faro-admin.cookies -X PATCH "$FARO/admin/api/settings" \
  -H 'Content-Type: application/json' \
  -d '{"retention": {"blob_days": 14}}'
```

The answer shows the settings now in effect. Registration modes are `invite-only`, `open` (needs `allowed_email_domains`; `["*"]` means any domain) and `closed`. Retention can only be set in days, from 1 to 3650. Settings changed this way are stored in the database and take priority over `faro.env` from then on.

**8. Invite a member:**

```sh
curl -s -b faro-admin.cookies -X POST "$FARO/admin/api/invites" \
  -H 'Content-Type: application/json' \
  -d '{"email": "jordan@example.org"}'
```

They get an email invitation, valid for 7 days. (Until the web and desktop apps are released, there's little they can do with it.)

**9. Sign out and delete the sign-in file.** `faro-admin.cookies` works like a password for 30 days, so don't leave it lying around:

```sh
curl -s -b faro-admin.cookies -X POST "$FARO/v1/auth/logout"
rm faro-admin.cookies
```

**Signing `curl` in.** Your browser signs in at `/signin`, but `curl` keeps its own sign-in. Ask for a sign-in link, which is emailed to you:

```sh
curl -s -X POST "$FARO/v1/auth/magic-link" \
  -H 'Content-Type: application/json' -d '{"email": "you@yourchurch.org"}'
```

The email contains a link ending in `#token=…`. Copy everything after `token=` (the link works once, for 15 minutes) and exchange it for a sign-in:

```sh
curl -s -c faro-admin.cookies -X POST "$FARO/v1/auth/magic-link/verify" \
  -H 'Content-Type: application/json' -d '{"token": "PASTE-THE-TOKEN-HERE"}'
```

---

## 7. Email (SMTP)

Faro needs to send email for sign-in links, invitations and alerts. Use an account at your existing email provider or a sending service. Put the details in `faro.env`, then apply them with `sudo docker compose up -d`.

| Provider | `FARO_SMTP_HOST` | Port / `FARO_SMTP_TLS` | Username / password |
|---|---|---|---|
| Google Workspace or Gmail | `smtp.gmail.com` | `587` / `starttls` | Full address, and an **app password** (needs 2-step verification on the account) |
| Microsoft 365 | `smtp.office365.com` | `587` / `starttls` | Full address and password; an Exchange admin must allow "Authenticated SMTP" for that mailbox. Microsoft is retiring password sign-in for SMTP, so if this fails, use a sending service instead |
| Mailgun | `smtp.mailgun.org` (EU: `smtp.eu.mailgun.org`) | `587` / `starttls` | The SMTP credentials from your Mailgun domain settings |
| Amazon SES | `email-smtp.REGION.amazonaws.com` | `587` / `starttls` | SES SMTP credentials (not your AWS login) |
| Anything else | your provider's "outgoing mail server" | `587` / `starttls`, or `465` / `tls` | as your provider says |

Notes:

- `FARO_SMTP_FROM` is the sender people see, like `Faro <faro@yourchurch.org>`. Most providers only allow the address of the account you sign in with, or of a domain you've verified with them.
- Many VPS providers block port 25. Use 587 or 465.
- If the password contains a `$`, wrap it in single quotes in `faro.env`: `FARO_SMTP_PASSWORD='pa$word'`.
- Plain unencrypted SMTP (`FARO_SMTP_TLS=none`) is only accepted for a mail relay on the same machine.
- Email settings can only be changed in `faro.env`, not through the admin API.

**Test it** in two ways:

1. `sudo docker compose exec faro faro-server doctor` connects and signs in to your mail server without sending anything ([section 8](#8-checking-your-instance-faro-server-doctor)).
2. The test email (the setup page's Email step, or step 5 of the `curl` tasks in [First run](#6-first-run-create-the-admin-account)) actually sends a message to you.

What the error codes mean:

| Code | Meaning | What to try |
|---|---|---|
| `not_configured` | No SMTP settings | Fill in `FARO_SMTP_HOST` and `FARO_SMTP_FROM`, then `sudo docker compose up -d` |
| `rejected` | The mail server refused: usually a wrong username or password, or a "From" address you're not allowed to use | Check the password (app password for Google), and `FARO_SMTP_FROM` |
| `connection` | Couldn't connect | Check the host name and port; the VPS provider may block the port |
| `tls` | Encryption failed | Port 587 goes with `starttls`, port 465 with `tls` |
| `timeout` | No answer in time | Wrong port, or blocked by a firewall |
| `temporary_rejection` | The server said "try later" | Wait and try again |
| `recipient_rejected` / `recipient_deferred` | Your own address was refused / postponed | Check the admin account's email address |
| `invalid_address` | An address couldn't be read | Check `FARO_SMTP_FROM`, e.g. `Faro <faro@yourchurch.org>` |

---

## 8. Checking your instance: `faro-server doctor`

`doctor` checks the configuration and prints a report. Run it after setup, after changing settings, and whenever something seems wrong:

```sh
sudo docker compose exec faro faro-server doctor
```

Example from a healthy instance:

```
faro-server doctor

[OK  ] public_url     https://faro.yourchurch.org
[OK  ] tls            automatic certificates for faro.yourchurch.org via ACME; port must be reachable
[OK  ] data_dir       /data (0700)
[OK  ] identity.key   present, mode 0600
[OK  ] database       sqlite reachable, schema up to date (4 migrations)
[OK  ] identity       instance inst_… matches identity.key
[OK  ] settings       registration invite-only, retention 90/30/90 days (headers/blobs/alerts), liveness grace 10800 s
[OK  ] deletions      no account deletions pending
[OK  ] smtp           smtp.example.org reachable
[OK  ] disk           18.2 GiB free
[OK  ] updates        release metadata version 12 (4 artifacts cached)
[OK  ] backups        not verifiable from here: schedule `faro-server backup --out …` and rotate copies

0 failure(s), 0 warning(s)
```

`FAIL` lines need fixing; `WARN` lines work but deserve a look. On a Postgres database `doctor` adds `[WARN] postgres       experimental, not supported in this release (the beta supports SQLite only)`, and `serve` logs the same warning at startup; Faro still runs. A `WARN` on `deletions` means an account deletion has waited more than a week past its 7-day hold: Faro deletes an account only after everyone has been emailed about it, so fix email (§7) and it goes ahead. Add `--no-smtp-check` to skip connecting to the mail server. `doctor` only reads; it never changes anything.

---

## 9. Backups and restore

A backup is one `.tar` file with everything needed to rebuild the instance: a consistent copy of the database, the **instance identity key**, and the encrypted attachments. It's safe to make while Faro is running.

**The identity key matters most.** Members' computers check it every time they connect. If you lose it, every member has to re-enroll every computer. Keep backups somewhere other than the server, and treat them as sensitive: anyone with the identity key could impersonate your instance (they still can't read reports, which are end-to-end encrypted).

In the Docker setup, your settings live in `faro.env`, which is **not** in the backup. Keep a copy of it somewhere safe too (it contains your email password).

### Make a backup

```sh
sudo docker compose exec faro faro-server backup --out /backups/faro-$(date +%F).tar
```

The file appears in the `faro/deploy/backups` folder on the server. Copy it off the server, for example from your own computer:

```sh
scp root@YOUR.SERVER.IP:faro/deploy/backups/faro-2026-11-24.tar .
```

(Adjust the path if you cloned Faro somewhere other than the login user's home folder.)

### Back up automatically every night

Open root's scheduled tasks with `sudo crontab -e` and add this line, replacing `/root/faro/deploy` with the full path to your `deploy` folder (`pwd` prints it). It makes a backup at 3:30 every night and deletes backups older than 30 days:

```
30 3 * * * cd /root/faro/deploy && docker compose exec -T faro faro-server backup --out /backups/faro-$(date +\%F).tar && find /root/faro/deploy/backups -name 'faro-*.tar' -mtime +30 -delete
```

**Why delete old backups:** Faro deletes old data on schedule (attachments after 30 days by default). Backups kept much longer than that would keep deleted data alive. Keep backups no longer than your retention period, both on the server and wherever you copy them.

**Deleted accounts stay in older backups.** When someone deletes their account (Settings → Delete your account), Faro waits 7 days, makes sure everyone was emailed, and then removes everything about them from the server. Backups made before that still hold their data until you delete those backups. The account page tells people this.

### Restore a backup

This replaces the instance's current data with the backup. Use the name of your backup file.

1. Put the backup file in the `deploy/backups` folder, and stop Faro:

   ```sh
   sudo docker compose stop faro
   ```

2. Replace the data with the backup's contents:

   ```sh
   sudo docker compose run --rm --no-deps --entrypoint sh faro -c \
     'rm -f /data/faro.db /data/faro.db-wal /data/faro.db-shm && tar -xf /backups/faro-2026-11-24.tar -C /data && chmod 600 /data/identity.key && chmod 700 /data'
   ```

3. Start Faro again and check it:

   ```sh
   sudo docker compose up -d
   sudo docker compose exec faro faro-server doctor
   ```

**Restoring brings deleted accounts back.** A backup made before someone's account was deleted still has their account, data and computers. Their computers would be accepted again if Faro is still installed on them. After a restore, check the People page in the admin console. If someone who deleted their account is listed again, tell them and ask them to delete it again. Their allies are told again when they do.

After a restore the log says "previous run did not shut down cleanly". That's expected: the backup was taken while Faro was running. Attachments uploaded after the backup was made, which the restored database doesn't know about, are cleaned up automatically after a day.

**Moving to a new server:** set up the new server with your `faro.env` (Path A steps 1 to 8), build the image with `sudo docker compose build`, then do restore steps 2 and 3 there and point your DNS at the new server. Faro refuses to start if the identity key and the database don't belong together, so a mixed-up restore can't go unnoticed.

**Postgres** (experimental, not supported in this release): the backup file then contains the identity key and attachments but not the database. `faro-server backup` prints how to back up the database with `pg_dump`; keep both files together.

---

## 10. Upgrading

1. **Make a backup first** ([section 9](#9-backups-and-restore)) and copy it off the server.
2. Download the new version and rebuild:

   ```sh
   cd faro
   git pull
   cd deploy
   sudo docker compose up -d --build
   ```

   If you use the prebuilt image (`FARO_IMAGE` in `deploy/.env`, as in [Path B](#4-path-b-a-raspberry-pi)), download the new image instead of building:

   ```sh
   cd faro/deploy
   git pull
   sudo docker compose pull faro
   sudo docker compose up -d
   ```

3. Check: `sudo docker compose exec faro faro-server version` and `sudo docker compose exec faro faro-server doctor`.

Database changes are applied automatically when the new version starts, and they only go forward: to go back to an older version, restore the backup you made in step 1.

While Faro is pre-alpha there are no release versions, and `git pull` gets the latest development code, which can be broken. Only do this on a test or pilot instance. Once releases exist, this guide will tell you to upgrade to a release instead.

### Updates for members' computers

Members' computers get Faro updates **through your instance**, not straight from the Faro project. Your instance downloads each release from the project, keeps a copy, and hands it to the computers that ask. That way a college lab with hundreds of computers downloads a release from the internet once.

Your instance can't change an update. Releases are signed by the Faro project, and every computer checks that signature itself before installing anything. A broken or compromised instance can *delay* updates, but it can't push its own code to members' computers or move them back to an older release. Your instance checks the signatures too, so it never stores or hands out a file the project didn't sign.

It needs two settings, in `faro.env` (or the `[updates]` section of `faro.toml`):

```sh
# The project's root of trust. The official image will include this file.
FARO_UPDATES_ROOT=/usr/share/faro/update-root.json
# Where the project publishes releases.
FARO_UPDATES_UPSTREAM=https://…
```

> Neither exists yet: the project hasn't published its first signed release. Until then the mirror stays off, and `doctor` says so with a `WARN` line.

Once it's on, the instance checks for a new release every hour (`FARO_UPDATES_REFRESH_SECS`). It stores what it downloads in `updates/` in the data folder. Backups leave that folder out, because it can always be downloaded again.

**Which releases computers get.** Choose this on the admin console's **Settings** page (or with `FARO_UPDATES_CHANNEL`):

- **Stable** (the default): each new release, once the project marks it stable.
- **One release behind** (`stable-1`): the newest release of the previous version. This suits managed computers, such as a college lab, that only take a release after it has been out for a while. Computers that already have a newer release keep it: Faro never moves a computer back.
- **Beta**: releases before they are marked stable, for people who want to test them.

**Check on it** with `sudo docker compose exec faro faro-server updates status`. It shows when the instance last checked, which release it has, and which files it holds. `doctor` warns when the latest check failed, or when the copy the instance holds is too old for computers to accept. The project re-signs its releases daily so that computers can tell an old copy from a current one.

**An instance without internet access** (air-gapped) leaves `FARO_UPDATES_UPSTREAM` unset. Copy a release folder from the project onto the server, then copy it into the container and load it (from the `deploy` folder):

```sh
sudo docker compose cp release-2027-01 faro:/tmp/release
sudo docker compose exec faro faro-server updates import --from /tmp/release
```

The running server serves the new release within a minute. Because the project re-signs releases daily, an air-gapped instance needs a fresh copy at least that often, or computers will refuse it as too old.

---

## 11. What you as the operator can and cannot see

Faro is built so that the people running an instance **can't** see members' screens, reports or alerts. Each instance publishes a plain-language notice of exactly what its operator can and can't see, generated from its own settings. Members are shown it before they sign up. Read yours:

```sh
curl -s https://faro.yourchurch.org/v1/privacy-notice
```

(If you install `jq` with `sudo apt-get install -y jq`, then `curl -s https://faro.yourchurch.org/v1/privacy-notice | jq -r .text` shows it as plain text.)

In short:

- **You can see** account names and email addresses, who is connected to whom, device names and when they last checked in, *when* events happen and their kind and urgency (but not their content), delivery problems, storage use, and network addresses (kept only in memory, for rate limiting).
- **You cannot see** reports, timelines, thumbnails, web addresses visited, or what triggered an alert: those are encrypted on members' computers, and only their chosen allies can decrypt them. Your server never has the keys.
- **You cannot** enroll a computer for someone else, make yourself someone's ally, or hide events from allies. Faro is for people who choose accountability for themselves; it must not be used to monitor anyone who hasn't opted in.
- **One honest limit:** members and allies who use the web app in a browser trust the operator not to tamper with the code the server sends them. The notice says so too, and a separate desktop app for allies is planned for those who don't want to rely on that.

Responsibilities that come with running an instance:

- You are the **data controller** for your instance (for example under GDPR, or FERPA considerations at a US college). The project gives no legal advice.
- **Do not enroll minors.** That's outside what Faro v1 is designed for.
- Keep the server updated (`sudo apt-get update && sudo apt-get upgrade`), keep backups, and keep `faro.env` and backup files private.

---

## 12. Without Docker: the binary and systemd

If you prefer to run `faro-server` directly (for example on an existing Debian or Ubuntu server), build it from source and use the systemd unit in `deploy/faro-server.service`.

1. **Build** (as your normal user). Building the web app (the setup page) needs **Node.js 22.17 or newer**. The `nodejs` packages in Debian and Ubuntu are older, so install a current version as [nodejs.org's download page](https://nodejs.org/en/download) shows for Linux, and check it with `node --version`. Then:

   ```sh
   sudo apt-get install -y build-essential git curl
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
   . "$HOME/.cargo/env"
   git clone https://github.com/faro-project/faro.git
   cd faro
   (cd web && npm ci && npm run build)
   FARO_REQUIRE_WEB=1 cargo build --release --locked -p faro-server
   ```

   `FARO_REQUIRE_WEB=1` stops the build if the web app is missing. Without it, the build still works but the server has no setup page.

2. **Install the binary, a user and the configuration:**

   ```sh
   sudo install -m 0755 target/release/faro-server /usr/local/bin/faro-server
   sudo useradd --system --user-group --home-dir /var/lib/faro --no-create-home --shell /usr/sbin/nologin faro
   sudo install -d -m 0750 -o root -g faro /etc/faro
   sudo install -m 0640 -o root -g faro server/faro.example.toml /etc/faro/faro.toml
   sudo nano /etc/faro/faro.toml
   ```

   In `faro.toml`, keep `data_dir = "/var/lib/faro"`, set `public_url` and the `[instance]` name, fill in `[smtp]`, and choose one HTTPS mode:
   - **built-in HTTPS:** `listen = "0.0.0.0:443"`, `behind_proxy = false`, and in `[tls]` set `acme_domain` and `acme_contact`;
   - **behind a proxy on this machine:** `listen = "127.0.0.1:8080"`, `behind_proxy = true`, and point the proxy at `http://127.0.0.1:8080`.

3. **Install and start the service:**

   ```sh
   sudo install -m 0644 deploy/faro-server.service /etc/systemd/system/faro-server.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now faro-server
   sudo journalctl -u faro-server | grep -A2 'setup token'
   ```

   Then continue with [First run](#6-first-run-create-the-admin-account). If you need a new setup token: `sudo -u faro faro-server init --config /etc/faro/faro.toml`.

4. **Everyday commands** in this setup:

   ```sh
   sudo -u faro faro-server doctor --config /etc/faro/faro.toml
   sudo install -d -m 0700 -o faro -g faro /var/backups/faro
   sudo -u faro faro-server backup --config /etc/faro/faro.toml --out /var/backups/faro/faro-$(date +%F).tar
   sudo journalctl -u faro-server -f
   ```

   In this setup the backup also contains `faro.toml` (and so your SMTP password). To restore: `sudo systemctl stop faro-server`, then as the `faro` user delete `/var/lib/faro/faro.db`, `faro.db-wal` and `faro.db-shm`, run `tar -xf BACKUP.tar -C /var/lib/faro`, and start the service again.

The unit runs Faro as the unprivileged `faro` user in a tight sandbox: it can only write to `/var/lib/faro`. It grants one capability, binding port 443, which you can remove when running behind a proxy (see the comments in the file).

---

## 13. Troubleshooting

**See what Faro is saying:** `sudo docker compose logs --tail 100 faro` (add `-f` to follow along). For more detail, add `FARO_LOG=debug` to `faro.env` and run `sudo docker compose up -d`; remove it again afterwards.

| Message or symptom | Cause and fix |
|---|---|
| `public_url … must use https://` | `FARO_PUBLIC_URL` must start with `https://`. |
| `tls.acme_domain must be the host of public_url` | `FARO_TLS_ACME_DOMAIN` must be exactly the domain in `FARO_PUBLIC_URL`. |
| `behind_proxy and built-in TLS are mutually exclusive` | You set both mode A (`FARO_TLS_ACME_…`) and mode B (`FARO_BEHIND_PROXY`). Keep one. |
| `warning: ignoring unknown environment variable FARO_…` | A typo in a setting name in `faro.env`. |
| `smtp.host and smtp.from must be set together` (or `username and password`) | Fill in both, or neither. |
| `the identity key … does not match …; refusing to start` | `identity.key` and the database come from different instances, usually after a partial restore. Restore both from the same backup. |
| Mode A: the browser or `curl` shows a certificate or connection error | Check that DNS points at this server (`ping faro.yourchurch.org`), that port 443 is open in the provider's and the server's firewall, and the log for ACME messages. While experimenting, add `FARO_TLS_ACME_PRODUCTION=false` to use Let's Encrypt's test service and avoid its rate limits (its certificates aren't trusted by browsers; remove the line when it works). |
| `curl http://…` doesn't answer | Faro only speaks HTTPS; use `https://`. |
| `docker compose ps` shows `unhealthy` | Look at the logs. The health check asks Faro for `/.well-known/faro` (or, with built-in HTTPS, only checks that the port is open). |
| `{"error":"rate_limited","message":"too many requests; slow down"}`, especially when many people sign up at once | Faro limits sign-in, setup and enrollment requests per address. Behind a proxy or tunnel, make sure `FARO_BEHIND_PROXY=true` is set, otherwise everyone shares one limit. Raise `FARO_RATE_LIMIT_PER_MINUTE` if needed. |
| `invalid_setup_token` | The token was mistyped, already used, replaced by a newer `init`, or older than 24 hours. Run `sudo docker compose exec faro faro-server init` for a new one. |
| Backup fails with `Permission denied` on `/backups` | Run `sudo chown 10001:10001 backups` in the `deploy` folder. |

Still stuck? Open an issue at <https://github.com/faro-project/faro/issues> with the output of `faro-server doctor` (it contains no secrets) and the relevant log lines. **Never post** `faro.env`, `identity.key`, backup files, setup tokens or sign-in links.

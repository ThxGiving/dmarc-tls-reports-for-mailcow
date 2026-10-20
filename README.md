# mailcow DMARC/TLS reports

Add-on for [mailcow-dockerized](https://github.com/mailcow/mailcow-dockerized) that collects the DMARC
aggregate (RUA) and SMTP TLS (TLS-RPT) reports other mail servers send about your domains, sends an alert
only when something is actually wrong, and shows everything on an admin-only page inside the mailcow UI
(`/admin/dmarc/`, optionally in the Apps menu). It runs as one small container next to mailcow.

Features:

- Uses mailcow's own admin login and session. No extra accounts, no extra web server.
- Setup assistant on the first visit: report mailbox (existing or new), alert recipients, Apps menu entry.
- Reads a dedicated report mailbox over IMAP with an app password limited to that mailbox, and deletes processed reports.
- Alerts only on TLS failures towards your MX, DMARC failures of mail sent by your own server, and unreadable reports.
- Looks like a regular mailcow page (Bootstrap 5.1, works with light and dark mode).
- Issue list with a short "what to do" for each entry. Issues can be marked as done and only come back if a newer report shows the same problem.
- Per-domain status, 52-week trend, results per receiver (Google, Microsoft, ...), TLS failures, spoofing sources with reverse DNS, and a hint when a domain is ready for `p=reject`.
- Detects your own server IPs the same way mailcow's DNS check does (`SNAT_TO_SOURCE` or ip4/ip6.mailcow.email).
- DNS assistant: lists the TXT records each domain needs (DMARC `rua`, TLS-RPT, external destination authorization) and checks them live.
- New reports are processed within seconds of arriving (IMAP IDLE on the report mailbox). A daily run catches anything that was missed.
- The time of the daily run is set in the settings tab.
- Uses the language selected in mailcow. All 31 mailcow UI languages are included (`lang/*.json`).
- Update-safe: only uses mailcow's extension points (`docker-compose.override.yml`, `data/conf/nginx/*.custom`,
  `0081-custom-mailcow.css`, App links).

## Requirements

- mailcow-dockerized with `docker compose` (tested with 2026-09)
- Nothing else on the host: no scripts, packages or system services, and no nginx restart is needed.

## Install

1. Add the service from [`docker-compose.override.yml.example`](docker-compose.override.yml.example) to
   `docker-compose.override.yml` in your mailcow folder (next to `mailcow.conf`; create the file if it doesn't exist).
2. Start it:
   ```bash
   docker compose up -d
   ```
3. Open `https://<mailcow-host>/admin/dmarc/` as mailcow admin and complete the setup assistant: choose or
   create the report mailbox, enter who gets alerts and whether the page should appear in the Apps menu.
   The page creates an app password for the report mailbox (IMAP and SMTP only), which the container uses.
4. Add the DNS records the DNS assistant lists:

| Record | Example |
|---|---|
| `_smtp._tls.<domain>` TXT | `v=TLSRPTv1; rua=mailto:reports@example.org` |
| `_dmarc.<domain>` TXT (add to `rua`) | `v=DMARC1; p=quarantine; rua=mailto:reports@example.org` |
| `<domain>._report._dmarc.<mailbox-domain>` TXT (only for other domains) | `v=DMARC1` |

First reports usually arrive one or two days later.

## Update

```bash
docker compose pull reports-mailcow
docker compose up -d reports-mailcow
```

The container puts the new version of the page in place itself.

## How it works

```
reports@ mailbox ──IMAP IDLE──► container (collector) ──► SQLite (volume, 12 months)
                                     │                         │
                 alert mail ◄─SMTP───┘                         └──► data/web/admin/dmarc/_data/dashboard.json
                (only on problems)                                         │
                                         mailcow UI (admin) ◄── index.php (protect_route, base.twig)
```

| Part | Location |
|---|---|
| Collector, database | container `reports-mailcow`, volume `reports-vol-1` |
| Web page | `data/web/admin/dmarc/` (copied there by the container) |
| Data for the page (not web-accessible) | `data/web/admin/dmarc/_data/` |
| nginx protection for `_data/` | `data/conf/nginx/site.mailcow-reports.custom` (written by the container) |
| Apps menu entry for admins only | marked block in `data/web/css/build/0081-custom-mailcow.css` (written by the container) |
| Mailbox access | app password of the report mailbox, IMAP + SMTP only, created by the setup assistant |

The container never gets the docker socket, the database or the vmail volume. It talks to dovecot (IMAPS)
and postfix (submission) inside `mailcow-network` and checks their certificate against `MAILCOW_HOSTNAME`.
The data folder belongs to php-fpm's user, so nginx cannot read it even before the snippet is loaded;
the container checks this and the setup stays locked until it is confirmed.

mailcow shows App links to every logged-in user. The CSS block hides the entry unless the page contains
mailcow's admin-only "Configuration" menu (browsers with `:has()` support). This is cosmetic only: the page
itself requires the mailcow admin login.

Logs: `docker compose logs reports-mailcow`

## Translations

All texts are in `lang/<mailcow locale>.json`, one file per mailcow UI language (`de-de.json`, `en-gb.json`, ...),
using the same locale codes as mailcow's `data/web/lang/`. The page shows the language selected in mailcow; missing languages or
missing keys fall back to English, so a partial translation is fine.

To add a language: copy `lang/en-gb.json` to e.g. `lang/fr-fr.json`, translate the values (keep the keys and
the `{placeholders}`), set `_name`, `_decimal` and `_thousands`, and rebuild the image. The language of
the alert mails is chosen under Settings (or `--language fr-fr`).

## Uninstall

Remove the service from `docker-compose.override.yml`, then:

```bash
docker compose up -d --remove-orphans
rm -r data/web/admin/dmarc data/conf/nginx/site.mailcow-reports.custom
docker volume rm mailcowdockerized_reports-vol-1      # collected data
```

Remove the block between `/* mailcow-report-dashboard: begin */` and `... end */` from
`data/web/css/build/0081-custom-mailcow.css`, the "DMARC/TLS reports" entry under System → Customize → App links,
and the app password "mailcow-report-dashboard" in the report mailbox's settings.

## Security notes

- The page is only reachable for mailcow admins (and valid admin API keys, as everywhere in mailcow);
  read-only API keys can view but not change anything. CSRF protection is mailcow's own token check.
- nginx blocks everything in the add-on folder except the page itself (`_data/`, `lang/`, dot files);
  The container verifies this through mailcow's nginx; until it is blocked, the page does not store the app password.
- Reports are untrusted input, anyone can send mail to the report mailbox. The collector therefore
  refuses XML with DOCTYPE/ENTITY declarations, limits sizes (20 MB per file, 50 MB per message,
  10 files per zip, 20000 records per report), truncates stored strings, sends at most 10 alert mails
  per day, does at most 40 new reverse-DNS lookups per run and deletes parked mail in `Unprocessed`
  after 30 days. Fake reports cannot be ruled out (DMARC reports are not authenticated); they can only
  add misleading data to the dashboard.
- Files the web server can write (`_data/settings.json`, `ack.json`) are read without following
  symlinks, never from FIFOs/devices, size-capped, and every value is validated.
- The container has no access to the docker socket, the mailcow database or other mailboxes. Its app password
  only works for the report mailbox and only for IMAP and SMTP; it can be revoked in mailcow at any time.

## License

MIT

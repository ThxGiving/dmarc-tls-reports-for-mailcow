# mailcow report dashboard

Add-on for [mailcow-dockerized](https://github.com/mailcow/mailcow-dockerized) that collects the DMARC
aggregate (RUA) and SMTP TLS (TLS-RPT) reports other mail servers send about your domains, sends an alert
only when something is actually wrong, and shows everything on an admin-only page inside the mailcow UI
(Apps menu).

Features:

- Uses mailcow's own admin login and session. No extra accounts, no extra web server.
- Reads a dedicated report mailbox (can be selected or created in the UI) and deletes processed reports.
- Alerts only on TLS failures towards your MX, DMARC failures of mail sent by your own server, and unreadable reports.
- Looks like a regular mailcow page (Bootstrap 5.1, works with light and dark mode).
- Issue list with a short "what to do" for each entry. Issues can be marked as done and only come back if a newer report shows the same problem.
- Per-domain status, 52-week trend, results per receiver (Google, Microsoft, ...), TLS failures, spoofing sources with reverse DNS, and a hint when a domain is ready for `p=reject`.
- Detects your own server IPs the same way mailcow's DNS check does (`SNAT_TO_SOURCE` or ip4/ip6.mailcow.email).
- DNS assistant: lists the TXT records each domain needs (DMARC `rua`, TLS-RPT, external destination authorization) and checks them live.
- New reports are processed as soon as they arrive (systemd path unit watching the mailbox, no polling). A daily run catches anything that was missed.
- Time of the daily run and a "run now" button are in the settings tab.
- Uses the language selected in mailcow. All 31 mailcow UI languages are included (`lang/*.json`).
- Update-safe: only uses mailcow's extension points (`data/conf/nginx/*.custom`, App links, own web folder excluded from git).

## Requirements

- mailcow-dockerized (tested with 2026-09) running on the host
- root on the host, `python3` ≥ 3.8 (stdlib only), systemd

## Install

```bash
git clone https://github.com/ThxGiving/mailcow-report-dashboard.git
cd mailcow-report-dashboard
sudo ./install.sh --language en --alert-to postmaster@example.org
```

Options: `--mailcow-dir`, `--mailbox`, `--alert-to`, `--language de|en`, `--own-ips`, `--slug`, `--app-name`,
`--no-app-link` (see `./install.sh --help`). Re-running the installer updates the add-on and keeps settings, data and the URL (`--slug`); options given on an update (e.g. `--alert-to`) change only those settings.

Then open **mailcow → Apps → Delivery reports** (or `https://<mailcow-host>/reports/`), go to **Settings**,
select or create the report mailbox and add the DNS records the DNS assistant lists:

| Record | Example |
|---|---|
| `_smtp._tls.<domain>` TXT | `v=TLSRPTv1; rua=mailto:reports@example.org` |
| `_dmarc.<domain>` TXT (add to `rua`) | `v=DMARC1; p=quarantine; rua=mailto:reports@example.org` |
| `<domain>._report._dmarc.<mailbox-domain>` TXT (only for other domains) | `v=DMARC1` |

First reports usually arrive one or two days later.

## How it works

```
reports@ mailbox ──doveadm──► collector (systemd, host) ──► SQLite (12 months)
                                     │                         │
                     alert mail ◄────┘                         └──► _data/dashboard.json
                (doveadm save, only on problems)                         │
                                         mailcow UI (admin) ◄── index.php (protect_route, base.twig)
```

| Part | Location |
|---|---|
| Collector, config, database | `/opt/mailcow-reports/` |
| Web page | `<mailcow>/data/web/<slug>/index.php` (git-excluded locally) |
| Data for the page (not web-accessible) | `<mailcow>/data/web/<slug>/_data/` |
| nginx protection for `_data/` | `<mailcow>/data/conf/nginx/site.mailcow-reports.custom` |
| Apps menu entry | mailcow App links (System → Customize) |
| Triggers | `mailcow-reports-mail.path` (new report delivered → process), `mailcow-reports.path` ("run now"), `mailcow-reports.timer` (hourly check for the daily safety-net run) |

Logs: `journalctl -u mailcow-reports`

## Translations

All texts are in `lang/<mailcow locale>.json`, one file per mailcow UI language (`de-de.json`, `en-gb.json`, ...),
using the same locale codes as mailcow's `data/web/lang/`. The page shows the language selected in mailcow; missing languages or
missing keys fall back to English, so a partial translation is fine.

To add a language: copy `lang/en-gb.json` to e.g. `lang/fr-fr.json`, translate the values (keep the keys and
the `{placeholders}`), set `_name`, `_decimal` and `_thousands`, and re-run `./install.sh`. The language of
the alert mails is chosen under Settings (or `--language fr-fr`).

## Uninstall

```bash
sudo ./uninstall.sh            # keeps collected data in /opt/mailcow-reports
sudo ./uninstall.sh --purge    # removes everything (the report mailbox is never deleted)
```

## About the instant processing

`mailcow-reports-mail.path` uses systemd's inotify support on the report mailbox's `Maildir/new`
folders inside mailcow's `vmail` Docker volume (a plain directory on the host, so events from the
dovecot container are seen by the host kernel). The add-on only watches these folders. Reading
and deleting always goes through `doveadm`, and no mailcow/dovecot configuration is changed.
It relies on mailcow's current storage layout (`<vmail volume>/<domain>/<localpart>/Maildir`); if
that ever changes, or the volume lives on network storage without inotify support, the watch simply
stops firing and the daily safety-net run still processes everything.

## Security notes

- The page is only reachable for mailcow admins (and valid admin API keys, as everywhere in mailcow);
  read-only API keys can view but not change anything. CSRF protection is mailcow's own token check.
- nginx blocks everything in the add-on folder except the page itself (`_data/`, `lang/`, dot files);
  `install.sh` verifies this over HTTPS and aborts if the data files were reachable.
- Reports are untrusted input, anyone can send mail to the report mailbox. The collector therefore
  refuses XML with DOCTYPE/ENTITY declarations, limits sizes (20 MB per file, 50 MB per message,
  10 files per zip, 20000 records per report), truncates stored strings, sends at most 10 alert mails
  per day, does at most 40 new reverse-DNS lookups per run and deletes parked mail in `Unprocessed`
  after 30 days. Fake reports cannot be ruled out (DMARC reports are not authenticated); they can only
  add misleading data to the dashboard.
- Files the web server can write (`_data/settings.json`, `ack.json`) are read without following
  symlinks, never from FIFOs/devices, size-capped, and every value is validated.
- The collector runs as root on the host because it uses `docker compose exec ... doveadm` (docker access
  is root-equivalent anyway). Its systemd units are sandboxed where that is compatible (read-only /usr
  and home, private /tmp, no new privileges, kernel/clock/hostname protection, 1 GB memory and
  30 min time limit). It does not open any port.

## License

MIT

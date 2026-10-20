#!/usr/bin/env bash
# mailcow-report-dashboard - installer
#
# Installs (or updates) the collector, the admin-only web page, an nginx snippet,
# an "Apps" menu entry and the systemd units (new-report trigger, "run now" trigger,
# daily safety-net timer) on a mailcow-dockerized host.
# Re-running it is safe: existing settings and collected data are kept.
#
# Usage: sudo ./install.sh [options]
#   --mailcow-dir DIR     mailcow-dockerized directory (default: /opt/mailcow-dockerized)
#   --mailbox ADDR        existing mailbox that receives the reports (optional - can be
#                         created/selected later in the web UI)
#   --alert-to ADDR[,..]  mailbox(es) on this server that get problem alerts
#   --language CODE       language of the alert mails: a file in lang/, e.g. de-de, en-gb
#                         (de/en accepted; default: en-gb or the current setting). The web
#                         page always follows the language chosen in mailcow.
#   --own-ips IP[,..]     fixed public IPs of this mail server (default: detected automatically
#                         on every run, exactly like mailcow's DNS check)
#   --slug NAME           URL path, https://<host>/<slug>/ (default: reports; on an update
#                         the slug of the existing installation)
#   --app-name NAME       label in mailcow's "Apps" menu (default: by language)
#   --no-app-link         do not add the "Apps" menu entry
# On an update, --mailbox/--alert-to/--language/--own-ips change the existing settings;
# options left out keep what was set in the web UI.
set -euo pipefail

MAILCOW_DIR=/opt/mailcow-dockerized
INSTALL_DIR=/opt/mailcow-reports
SLUG=""
MAILBOX=""
ALERT_TO=""
LANGUAGE=""
SET_MAILBOX=0
SET_ALERT=0
OWN_IPS=""
OWN_IPS_MANUAL=0
APP_NAME=""
APP_LINK=1
SRC="$(cd "$(dirname "$0")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --mailcow-dir) MAILCOW_DIR="$2"; shift 2 ;;
    --mailbox) MAILBOX="$2"; SET_MAILBOX=1; shift 2 ;;
    --alert-to) ALERT_TO="$2"; SET_ALERT=1; shift 2 ;;
    --language) LANGUAGE="$2"; shift 2 ;;
    --own-ips) OWN_IPS="$2"; OWN_IPS_MANUAL=1; shift 2 ;;
    --slug) SLUG="$2"; shift 2 ;;
    --app-name) APP_NAME="$2"; shift 2 ;;
    --no-app-link) APP_LINK=0; shift ;;
    -h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- checks ---------------------------------------------------------------
[ "$(id -u)" = 0 ] || die "run as root"
[ -f "$MAILCOW_DIR/mailcow.conf" ] || die "no mailcow.conf in $MAILCOW_DIR (use --mailcow-dir)"
command -v python3 >/dev/null || die "python3 is required"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || die "python3 >= 3.8 is required"
docker compose version >/dev/null 2>&1 || die "docker compose (v2) is required"
cd "$MAILCOW_DIR"
RUNNING="$(docker compose ps --services --status running 2>/dev/null || true)"   # no "| grep -q" under pipefail (SIGPIPE)
grep -qx 'dovecot-mailcow' <<<"$RUNNING" || die "mailcow is not running"

# update of an existing installation: keep its slug, never create a second copy by accident
OLD_SLUG="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("web_slug",""))' "$INSTALL_DIR/config.json" 2>/dev/null || true)"
if [ -n "$OLD_SLUG" ] && [ -n "$SLUG" ] && [ "$SLUG" != "$OLD_SLUG" ]; then
  die "already installed with --slug $OLD_SLUG - re-run without --slug, or run ./uninstall.sh first (collected data is kept)"
fi
SLUG="${SLUG:-${OLD_SLUG:-reports}}"
[[ "$SLUG" =~ ^[a-z0-9-]+$ ]] || die "invalid --slug"
WEB_DIR="$MAILCOW_DIR/data/web/$SLUG"
SETTINGS="$WEB_DIR/_data/settings.json"
SET_LANG=0; [ -n "$LANGUAGE" ] && SET_LANG=1
CUR_LANG="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("language",""))' "$SETTINGS" 2>/dev/null || true)"
LANGUAGE="${LANGUAGE:-${CUR_LANG:-en-gb}}"
case "$LANGUAGE" in de) LANGUAGE=de-de ;; en) LANGUAGE=en-gb ;; esac   # short codes from version <= 0.3
[[ "$LANGUAGE" =~ ^[a-z]{2}-[a-z]{2}$ ]] && [ -f "$SRC/lang/$LANGUAGE.json" ] \
  || die "--language: no lang/$LANGUAGE.json (available: $(cd "$SRC/lang" && ls *.json | sed 's/\.json$//' | tr '\n' ' '))"
if [ -e "$WEB_DIR" ] && [ ! -f "$WEB_DIR/.mailcow-report-dashboard" ]; then
  die "$WEB_DIR already exists and was not created by this installer - choose another --slug"
fi

conf() { { grep -E "^$1=" mailcow.conf || true; } | tail -1 | cut -d= -f2-; }   # missing key = empty, not a silent abort (set -e + pipefail)
HOSTNAME_MC="$(conf MAILCOW_HOSTNAME)"
[ -n "$HOSTNAME_MC" ] || die "MAILCOW_HOSTNAME is not set in mailcow.conf"
[ -n "$APP_NAME" ] || APP_NAME="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("app_name") or "Delivery reports")' "$SRC/lang/$LANGUAGE.json")"

public_only() {  # drop private/loopback/link-local addresses (split-horizon DNS, /etc/hosts)
  python3 -c 'import ipaddress,sys
def ok(a):
    try:
        return ipaddress.ip_address(a).is_global
    except ValueError:
        return False
print(",".join(a for a in sys.argv[1:] if ok(a)))' "$@"
}
if [ -z "$OWN_IPS" ]; then
  OWN_IPS="$(public_only $(getent ahosts "$HOSTNAME_MC" | awk '{print $1}' | sort -u))"
  if [ -z "$OWN_IPS" ] && command -v curl >/dev/null; then   # behind NAT / internal DNS: ask outside
    OWN_IPS="$(public_only $(curl -4 -fsS -m 5 https://api.ipify.org 2>/dev/null) $(curl -6 -fsS -m 5 https://api64.ipify.org 2>/dev/null))"
  fi
  [ -n "$OWN_IPS" ] && say "Own public server IPs: $OWN_IPS" || say "Could not detect public IPs - set them later in the web UI (Settings)"
fi

mailbox_exists() {
  docker compose exec -T dovecot-mailcow doveadm auth cache flush >/dev/null 2>&1 || true
  docker compose exec -T dovecot-mailcow doveadm user "$1" </dev/null >/dev/null 2>&1
}
if [ -n "$MAILBOX" ] && ! mailbox_exists "$MAILBOX"; then
  die "mailbox $MAILBOX does not exist - create it in mailcow (or later via the web UI) and re-run"
fi
for a in ${ALERT_TO//,/ }; do mailbox_exists "$a" || die "alert mailbox $a does not exist on this server"; done

# --- collector ------------------------------------------------------------
say "Installing collector to $INSTALL_DIR"
install -d -m 700 "$INSTALL_DIR"
install -m 700 "$SRC/collector/mailcow_reports.py" "$INSTALL_DIR/mailcow_reports.py"
if [ ! -f "$INSTALL_DIR/config.json" ]; then
  python3 - "$INSTALL_DIR/config.json" "$MAILCOW_DIR" "$SLUG" "https://$HOSTNAME_MC/$SLUG/" <<'PY'
import json, sys
path, mc, slug, url = sys.argv[1:]
json.dump({"mailcow_dir": mc, "web_slug": slug, "public_url": url, "retention_days": 365, "domains": "auto"},
          open(path, "w"), indent=2)
PY
  chmod 600 "$INSTALL_DIR/config.json"
fi

# --- web page -------------------------------------------------------------
say "Installing web page to $WEB_DIR"
install -d -m 755 "$WEB_DIR"
install -d -m 750 -o 82 -g 82 "$WEB_DIR/_data"      # 82 = www-data in php-fpm-mailcow
install -m 644 "$SRC/web/index.php" "$WEB_DIR/index.php"
install -d -m 755 "$WEB_DIR/lang"
rm -f "$WEB_DIR"/lang/*.json
install -m 644 "$SRC"/lang/*.json "$WEB_DIR/lang/"
touch "$WEB_DIR/.mailcow-report-dashboard"
# mailcow runs PHP with opcache.validate_timestamps=Off: gracefully reload php-fpm so an updated page is picked up
docker compose exec -T php-fpm-mailcow sh -c 'kill -USR2 1' >/dev/null 2>&1 || true
# new install: write defaults; update: only change what was given on the command line
python3 - "$SETTINGS" "$MAILBOX" "$ALERT_TO" "$OWN_IPS" "$LANGUAGE" "$OWN_IPS_MANUAL" "$SET_MAILBOX" "$SET_ALERT" "$SET_LANG" <<'PY'
import json, os, sys
path, mb, alert, ips, lang, manual, set_mb, set_alert, set_lang = sys.argv[1:]
ips = [i for i in ips.split(",") if i]
if not os.path.exists(path):
    cur = {"mailbox": mb, "alert_to": alert, "own_ips": ips, "own_ips_mode": "manual" if manual == "1" else "auto",
           "language": lang, "run_time": "07:30"}
else:
    cur = json.load(open(path))
    if set_mb == "1": cur["mailbox"] = mb
    if set_alert == "1": cur["alert_to"] = alert
    if set_lang == "1": cur["language"] = lang
    if manual == "1": cur["own_ips"], cur["own_ips_mode"] = ips, "manual"
tmp = path + ".install"
with open(tmp, "w") as f:
    json.dump(cur, f, indent=2)
os.replace(tmp, path)
PY
chown 82:82 "$SETTINGS"; chmod 640 "$SETTINGS"
# keep mailcow's git tree clean (update.sh) without touching tracked files
if [ -d .git/info ]; then
  grep -qxF "data/web/$SLUG/" .git/info/exclude 2>/dev/null || echo "data/web/$SLUG/" >> .git/info/exclude
fi

# --- nginx ----------------------------------------------------------------
say "Protecting /$SLUG/_data/ in nginx"
sed "s/__SLUG__/$SLUG/g" "$SRC/nginx/site.mailcow-reports.custom.template" > data/conf/nginx/site.mailcow-reports.custom
if ! docker compose exec -T nginx-mailcow nginx -t >/dev/null 2>&1; then
  rm -f data/conf/nginx/site.mailcow-reports.custom   # never leave a snippet that breaks nginx on its next restart
  die "nginx config test failed - snippet removed, nginx unchanged"
fi
docker compose exec -T nginx-mailcow nginx -s reload >/dev/null 2>&1
# self-test: the data files must not be reachable over HTTPS
HTTPS_PORT_MC="$(conf HTTPS_PORT)"; HTTPS_BIND_MC="$(conf HTTPS_BIND)"
case "$HTTPS_BIND_MC" in ""|0.0.0.0|::|"[::]") HTTPS_BIND_MC=127.0.0.1 ;; esac
if command -v curl >/dev/null; then
  sleep 1
  CODE="$(curl -sk -o /dev/null -w '%{http_code}' -m 10 --resolve "$HOSTNAME_MC:${HTTPS_PORT_MC:-443}:$HTTPS_BIND_MC" \
          "https://$HOSTNAME_MC:${HTTPS_PORT_MC:-443}/$SLUG/_data/settings.json" || true)"
  case "$CODE" in
    404|403) say "Check: /$SLUG/_data/ is not reachable (HTTP $CODE)" ;;
    200) die "SECURITY: /$SLUG/_data/settings.json is publicly reachable - nginx did not load data/conf/nginx/site.mailcow-reports.custom" ;;
    *) say "Note: could not verify that /$SLUG/_data/ is blocked (HTTP ${CODE:-none}) - please check manually" ;;
  esac
fi

# --- Apps menu (mailcow's own "App links", editable under System → Customize) --
if [ "$APP_LINK" = 1 ]; then
  say "Adding \"$APP_NAME\" to mailcow's Apps menu"
  REDISPASS="$(conf REDISPASS)"
  rcli() { docker compose exec -T redis-mailcow redis-cli ${REDISPASS:+-a "$REDISPASS"} --no-auth-warning "$@"; }
  CUR="$(rcli GET APP_LINKS | tr -d '\r')"
  NEW="$(python3 - "$CUR" "$APP_NAME" "/$SLUG/" <<'PY'
import json, sys
cur, name, link = sys.argv[1:]
try:
    links = json.loads(cur) if cur.strip() else []
except ValueError:
    links = []
links = [l for l in links if not any(v.get("link") == link for v in l.values())]
links.append({name: {"link": link, "user_link": link, "hide": True}})
print(json.dumps(links))
PY
)"
  rcli SET APP_LINKS "$NEW" >/dev/null
fi

# --- systemd --------------------------------------------------------------
say "Installing systemd units: new-report trigger, run-now trigger, daily safety-net timer"
install -m 644 "$SRC/systemd/mailcow-reports.service" /etc/systemd/system/mailcow-reports.service
install -m 644 "$SRC/systemd/mailcow-reports.timer" /etc/systemd/system/mailcow-reports.timer
install -m 644 "$SRC/systemd/mailcow-reports-mail.service" /etc/systemd/system/mailcow-reports-mail.service
sed "s#__DATA_DIR__#$WEB_DIR/_data#" "$SRC/systemd/mailcow-reports.path.template" > /etc/systemd/system/mailcow-reports.path
# mailcow-reports-mail.path (inotify on the report mailbox) is written by the collector itself,
# so it follows mailbox changes made in the web UI
systemctl daemon-reload
systemctl enable --now mailcow-reports.timer mailcow-reports.path >/dev/null 2>&1

say "Building the dashboard"
python3 "$INSTALL_DIR/mailcow_reports.py" --export-only
chown 82:82 "$WEB_DIR/_data/dashboard.json" 2>/dev/null || true

cat <<EOF

Done. Open https://$HOSTNAME_MC/$SLUG/ (mailcow admin login), or mailcow → Apps → $APP_NAME.
$( grep -q '"mailbox": ""' "$SETTINGS" && echo "Next: Settings tab → create or select the report mailbox." )
The Settings tab lists the DNS TXT records every domain needs (DMARC rua + TLS-RPT).
Logs: journalctl -u mailcow-reports   ·   Run now: Settings tab → "Run now" (or: touch $WEB_DIR/_data/run-now)
EOF

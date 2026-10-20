#!/usr/bin/env bash
# mailcow-report-dashboard - uninstaller
# Usage: sudo ./uninstall.sh [--mailcow-dir DIR] [--purge]
#   --purge   also delete collected data (/opt/mailcow-reports incl. database)
# The report mailbox itself is never deleted.
set -euo pipefail
MAILCOW_DIR=/opt/mailcow-dockerized; PURGE=0
while [ $# -gt 0 ]; do case "$1" in --mailcow-dir) MAILCOW_DIR="$2"; shift 2;; --purge) PURGE=1; shift;; *) echo "Unknown option $1"; exit 1;; esac; done
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
cd "$MAILCOW_DIR"
SLUG="$(python3 -c 'import json;print(json.load(open("/opt/mailcow-reports/config.json")).get("web_slug","reports"))' 2>/dev/null || echo reports)"
systemctl disable --now mailcow-reports.timer mailcow-reports.path mailcow-reports-mail.path 2>/dev/null || true
rm -f /etc/systemd/system/mailcow-reports.service /etc/systemd/system/mailcow-reports.timer /etc/systemd/system/mailcow-reports.path \
      /etc/systemd/system/mailcow-reports-mail.service /etc/systemd/system/mailcow-reports-mail.path
systemctl daemon-reload
[ -f "data/web/$SLUG/.mailcow-report-dashboard" ] && rm -rf "data/web/$SLUG"
sed -i "\#^data/web/$SLUG/\$#d" .git/info/exclude 2>/dev/null || true
rm -f data/conf/nginx/site.mailcow-reports.custom
docker compose exec -T nginx-mailcow nginx -s reload >/dev/null 2>&1 || true
REDISPASS="$(grep -E '^REDISPASS=' mailcow.conf | cut -d= -f2- || true)"
rcli() { docker compose exec -T redis-mailcow redis-cli ${REDISPASS:+-a "$REDISPASS"} --no-auth-warning "$@"; }
CUR="$(rcli GET APP_LINKS | tr -d '\r')"
NEW="$(python3 -c 'import json,sys
try: l=json.loads(sys.argv[1] or "[]")
except ValueError: l=[]
print(json.dumps([x for x in l if not any(v.get("link")==sys.argv[2] for v in x.values())]))' "$CUR" "/$SLUG/")"
rcli SET APP_LINKS "$NEW" >/dev/null
[ "$PURGE" = 1 ] && rm -rf /opt/mailcow-reports
echo "mailcow-report-dashboard removed.$( [ "$PURGE" = 1 ] || echo " Data kept in /opt/mailcow-reports (use --purge to delete).")"

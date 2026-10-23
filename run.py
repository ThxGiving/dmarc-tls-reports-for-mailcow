#!/usr/bin/env python3
"""Container entrypoint for mailcow-report-dashboard.

On start it puts the web page and the nginx snippet into mailcow's data folders (mounted
volumes), then loops:
  - IMAP IDLE on the report mailbox: new reports are processed within seconds
  - "Run now" button and the daily run: handled by the collector's --scheduled mode
The page is usable only after nginx has loaded the snippet that blocks _data/; until then
the settings page refuses to store the app password (see _data/container.json).
"""
import filecmp, glob, hashlib, imaplib, json, os, re, shutil, socket, ssl, subprocess, sys, time

APP = os.path.dirname(os.path.abspath(__file__))
ENV = os.environ
NGINX_DIR = ENV.get("NGINX_CONF_DIR", "/nginx-conf")
SLUG = ENV.get("SLUG", "admin/dmarc").strip("/")
HOSTNAME = ENV.get("MAILCOW_HOSTNAME", "")
HTTPS_PORT = int(ENV.get("HTTPS_PORT", "443"))
WEB_DIR = ENV.get("PAGE_DIR", "/page")                 # mailcow's data/web/<SLUG>, mounted
DATA_DIR = os.path.join(WEB_DIR, "_data")
CRED = os.path.join(DATA_DIR, "credentials.json")
SETTINGS = os.path.join(DATA_DIR, "settings.json")
STATUS = os.path.join(DATA_DIR, "container.json")
MARKER = os.path.join(WEB_DIR, ".mailcow-reports")
SNIPPET = os.path.join(NGINX_DIR, "site.mailcow-reports.custom")
CSS_FILE = os.path.join(ENV.get("CSS_DIR", "/mailcow-css"), "0081-custom-mailcow.css")   # mailcow's custom CSS
CSS_BEGIN, CSS_END = "/* mailcow-report-dashboard: begin */", "/* mailcow-report-dashboard: end */"
WWW = 82                                            # www-data in php-fpm-mailcow
POLL = 30
STARTUP_GRACE = 300            # after a (re)start mailcow's nginx/php-fpm may need a moment
VERSION = ENV.get("APP_VERSION", "dev")


def log(msg):
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}", flush=True)


def copy_if_changed(src, dst, mode=0o644):
    if os.path.exists(dst) and filecmp.cmp(src, dst, shallow=False):
        return False
    tmp = dst + ".tmp"
    shutil.copyfile(src, tmp)
    os.chmod(tmp, mode)
    os.replace(tmp, dst)
    return True


def deploy():
    if not re.match(r"^[a-z0-9][a-z0-9_-]{0,40}(/[a-z0-9][a-z0-9_-]{0,40})?$", SLUG):
        sys.exit(f"invalid SLUG {SLUG!r}")
    if not os.path.exists(MARKER) and [n for n in os.listdir(WEB_DIR) if n != "lang"]:
        sys.exit(f"data/web/{SLUG} is not empty and was not created by this add-on - choose another SLUG")
    os.makedirs(os.path.join(WEB_DIR, "lang"), exist_ok=True)
    open(MARKER, "a").close()
    # mailcow runs PHP with opcache.validate_timestamps=Off: a changed file would not be picked up
    # until php-fpm restarts. So the page gets a new file name per version and index.php - which
    # never changes - loads the version named in .version.
    src = os.path.join(APP, "web", "index.php")
    with open(src, "rb") as f:
        ver = hashlib.sha256(f.read()).hexdigest()[:12]
    page = f"page-{ver}.php"
    changed = copy_if_changed(src, os.path.join(WEB_DIR, page))
    changed |= copy_if_changed(os.path.join(APP, "web", "loader.php"), os.path.join(WEB_DIR, "index.php"))
    os.makedirs(DATA_DIR, mode=0o750, exist_ok=True)
    with open(os.path.join(DATA_DIR, "version.tmp"), "w") as f:     # _data: not readable for nginx
        f.write(ver)
    os.chmod(os.path.join(DATA_DIR, "version.tmp"), 0o644)
    os.replace(os.path.join(DATA_DIR, "version.tmp"), os.path.join(DATA_DIR, "version"))
    if os.path.exists(os.path.join(WEB_DIR, ".version")):
        os.remove(os.path.join(WEB_DIR, ".version"))
    for old in glob.glob(os.path.join(WEB_DIR, "page-*.php")):
        if os.path.basename(old) != page:
            os.remove(old)
    for name in os.listdir(os.path.join(APP, "lang")):
        if name.endswith(".json"):
            changed |= copy_if_changed(os.path.join(APP, "lang", name), os.path.join(WEB_DIR, "lang", name))
    os.makedirs(DATA_DIR, mode=0o750, exist_ok=True)
    os.chown(DATA_DIR, WWW, WWW)
    os.chmod(DATA_DIR, 0o750)
    with open(os.path.join(APP, "nginx", "site.mailcow-reports.custom.template")) as f:
        snippet = f.read().replace("__SLUG__", SLUG)
    current = open(SNIPPET).read() if os.path.exists(SNIPPET) else None
    if current != snippet:
        with open(SNIPPET + ".tmp", "w") as f:
            f.write(snippet)
        os.replace(SNIPPET + ".tmp", SNIPPET)
        log("nginx snippet written (active after the next nginx restart; _data is already blocked by file permissions)")
    if changed:
        log(f"web page deployed to data/web/{SLUG}")


def _get(path):
    """Status code of a GET through mailcow's nginx (internal hop, certificate not checked)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    host = HOSTNAME or "nginx"
    with socket.create_connection((ENV.get("NGINX_HOST", "nginx"), HTTPS_PORT), timeout=10) as raw, \
            ctx.wrap_socket(raw, server_hostname=host) as s:
        s.sendall(f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        head = s.recv(256).split(b"\r\n", 1)[0]
    parts = head.split(b" ")
    return parts[1].decode() if len(parts) > 1 else "?"


def ensure_menu_css():
    """mailcow shows App links to every user. This block in mailcow's custom CSS file hides our entry
    unless the page has the admin-only "Configuration" menu item. Cosmetic only - the page itself
    checks the admin login. Other content of the file is kept."""
    if not os.path.isdir(os.path.dirname(CSS_FILE)):
        return
    link = f"/{SLUG}/"
    block = (f"{CSS_BEGIN}\n@supports selector(:has(a)) {{\n"
             f"  body:not(:has(a[href=\"/admin/system\"])) .dropdown-menu li:has(> a[href=\"{link}\"]) {{ display: none !important; }}\n"
             f"}}\n{CSS_END}\n")
    try:
        with open(CSS_FILE) as f:
            css = f.read()
    except FileNotFoundError:
        css = ""
    if CSS_BEGIN in css and CSS_END in css:
        new = css[:css.index(CSS_BEGIN)] + block + css[css.index(CSS_END) + len(CSS_END):].lstrip("\n")
    else:
        new = css + ("\n" if css and not css.endswith("\n") else "") + block
    if new != css:
        with open(CSS_FILE + ".tmp", "w") as f:
            f.write(new)
        os.chmod(CSS_FILE + ".tmp", 0o644)
        os.replace(CSS_FILE + ".tmp", CSS_FILE)
        log("Apps menu entry limited to admins (data/web/css/build/0081-custom-mailcow.css)")


def protected(quiet=False):
    """True only if nginx answers 403/404 for a file in _data/ while the page itself answers,
    i.e. we really talked to mailcow's vhost and it refuses to serve the data folder."""
    probe = os.path.join(DATA_DIR, "probe.txt")
    with open(probe, "w") as f:
        f.write("probe")
    try:
        data_code, page_code = _get(f"/{SLUG}/_data/probe.txt"), _get(f"/{SLUG}/")
    except OSError as e:
        if not quiet:
            log(f"protection check failed: {e}")
        return False
    finally:
        os.remove(probe)
    ok = data_code in ("403", "404") and page_code in ("200", "301", "302")
    if not ok and not quiet:
        log(f"protection check: _data -> {data_code}, page -> {page_code}")
    return ok


def write_status(prot):
    tmp = STATUS + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"version": VERSION, "protected": prot, "checked": int(time.time()), "slug": SLUG}, f)
    os.chown(tmp, WWW, WWW)
    os.chmod(tmp, 0o640)
    os.replace(tmp, STATUS)


def run_collector(*args):
    r = subprocess.run([sys.executable, os.path.join(APP, "collector", "mailcow_reports.py"), *args],
                       capture_output=True, text=True, timeout=1800)
    for line in (r.stdout + r.stderr).strip().splitlines():
        log(line)


class _IMAP(imaplib.IMAP4_SSL):
    def _create_socket(self, timeout):
        sock = socket.create_connection((self.host, self.port), timeout)
        return self.ssl_context.wrap_socket(sock, server_hostname=HOSTNAME or self.host)


class Poller:
    """Keeps one IMAP connection and asks dovecot whether INBOX/Junk contain mail."""
    def __init__(self):
        self.conn, self.key = None, None

    def close(self):
        if self.conn:
            try:
                self.conn.logout()
            except (imaplib.IMAP4.error, OSError):
                pass
        self.conn = None

    def wait_for_mail(self, seconds):
        """True as soon as the report mailbox has mail: checks INBOX/Junk, then waits up to
        `seconds` with IMAP IDLE on INBOX, so dovecot pushes new reports within a second."""
        try:
            with open(CRED) as f:
                cred = json.load(f)
            key = (cred.get("user"), cred.get("password"))
        except (OSError, ValueError, AttributeError):
            self.close()
            time.sleep(seconds)
            return False
        if key != self.key:
            self.close()
            self.key = key
        try:
            if self.conn is None:
                ctx = ssl.create_default_context()
                if ENV.get("TLS_VERIFY", "1") == "0":
                    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                self.conn = _IMAP(ENV.get("IMAP_HOST", "dovecot"), int(ENV.get("IMAP_PORT", "993")), ssl_context=ctx, timeout=60)
                self.conn.login(*key)
            for folder in ("INBOX", "Junk"):
                typ, data = self.conn.status(f'"{folder}"', "(MESSAGES)")
                m = re.search(rb"MESSAGES (\d+)", data[0] or b"") if typ == "OK" else None
                if m and int(m.group(1)):
                    return True
            self.conn.select("INBOX", readonly=True)
            with self.conn.idle(duration=seconds) as idler:
                for typ, data in idler:
                    if typ == "EXISTS" and data and int(data[0]):
                        return True
            return False
        except (imaplib.IMAP4.error, OSError, ValueError) as e:
            log(f"imap: {e}")
            self.close()
            time.sleep(min(seconds, 10))
            return False


def main():
    started = time.time()
    deploy()
    ensure_menu_css()
    prot = protected(quiet=True)
    write_status(prot)
    log(f"started, version {VERSION}, _data protected: {prot}" + ("" if prot else " (waiting for mailcow's web server)"))
    if not os.path.exists(CRED):
        log(f"not set up yet: open https://{HOSTNAME or '<mailcow>'}/{SLUG}/ as mailcow admin")
    run_collector("--export-only")
    poller, last_sched, last_prot, warned = Poller(), 0, time.time(), False
    while True:
        now = time.time()
        starting = now - started < STARTUP_GRACE
        if not prot and now - last_prot > (10 if starting else 60):
            prot, last_prot = protected(quiet=starting), now
            write_status(prot)
            if prot:
                log("_data is protected now")
            elif not starting and not warned:
                log("_data still not confirmed as protected; setup stays locked (see the message on the page)")
                warned = True
        elif prot and now - last_prot > 3600:         # re-check hourly
            prot, last_prot = protected(), now
            write_status(prot)
        if os.path.lexists(os.path.join(DATA_DIR, "run-now")) or now - last_sched > 300:
            run_collector("--scheduled")
            last_sched = now
        if not prot:
            time.sleep(10 if starting else POLL)
        elif poller.wait_for_mail(POLL):           # returns early when dovecot announces new mail
            run_collector()


if __name__ == "__main__":
    main()

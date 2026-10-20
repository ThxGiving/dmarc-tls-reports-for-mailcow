#!/usr/bin/env python3
"""mailcow report dashboard - collector.

Reads DMARC aggregate (RUA) and SMTP TLS (TLS-RPT) reports from a dedicated
mailcow mailbox, stores them in SQLite, alerts by mail only on real problems and
exports a JSON snapshot that the admin-only web page renders.

Runs daily via systemd (mailcow-reports.timer).
Options: --scheduled     run only if due (daily time from the web UI) or if "run now" was requested
         (without option: process now - used by mailcow-reports-mail.path, which fires as soon as
          a new report is delivered to the mailbox)
         --dry-run       parse only: no DB writes, no deletion, alert mail printed
         --export-only   rebuild the dashboard JSON from the database
Config:  /opt/mailcow-reports/config.json (see config.example.json)
"""
import email, email.policy, fcntl, gzip, io, ipaddress, json, os, re, socket, sqlite3, stat, subprocess, sys, tempfile, time, zipfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parsedate_to_datetime

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("MAILCOW_REPORTS_CONFIG", os.path.join(BASE, "config.json"))
with open(CONFIG_PATH) as _f:
    CFG = json.load(_f)

COMPOSE_DIR = CFG.get("mailcow_dir", "/opt/mailcow-dockerized")
WEB_SLUG = CFG.get("web_slug", "reports").strip("/")
DATA_DIR = os.path.join(COMPOSE_DIR, "data/web", WEB_SLUG, "_data")
EXPORT_PATH = os.path.join(DATA_DIR, "dashboard.json")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")   # edited in the web UI


def read_untrusted_json(path, limit=1024 * 1024):
    """JSON file from DATA_DIR, which the web server (www-data) can write. This runs as root, so:
    never follow a symlink, never block on a FIFO/device, cap the size - and validate every value."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            raise ValueError(f"{os.path.basename(path)}: not a regular file or too large")
        with os.fdopen(fd, "rb") as f:
            fd = None
            return json.loads(f.read(limit + 1))
    finally:
        if fd is not None:
            os.close(fd)


try:
    _settings = read_untrusted_json(SETTINGS_PATH)
    if isinstance(_settings, dict):
        CFG.update({k: v for k, v in _settings.items() if k in ("mailbox", "alert_to", "own_ips", "own_ips_mode", "language", "run_time")})
except (OSError, ValueError):
    pass

ADDR_RE = re.compile(r"^[a-z0-9._+-]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)+$")
MAILBOX = str(CFG.get("mailbox", "")).strip().lower()
if not ADDR_RE.match(MAILBOX):
    MAILBOX = ""
ALERT_TO = [a.strip().lower() for a in str(CFG.get("alert_to", "")).split(",")
            if ADDR_RE.match(a.strip().lower()) and a.strip().lower() != MAILBOX]   # never alert into the report box
OWN_IPS_MODE = CFG.get("own_ips_mode", "auto")               # "auto" (like mailcow) or "manual"
OWN_IPS = set()                                             # filled in main() via own_ips()
DB_PATH = CFG.get("db_path", os.path.join(BASE, "reports.db"))
PUBLIC_URL = CFG.get("public_url", "")
LANG = str(CFG.get("language", "en-gb")).lower()                # alert mails; the web page follows mailcow's UI language
if not re.match(r"^[a-z]{2}(-[a-z]{2})?$", LANG):
    LANG = "en-gb"
RETENTION_DAYS = int(CFG.get("retention_days", 365))
RUN_TIME = str(CFG.get("run_time", "07:30"))                 # daily safety-net run (HH:MM, server time)
if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", RUN_TIME):
    RUN_TIME = "07:30"
RUN_NOW_FLAG = os.path.join(DATA_DIR, "run-now")            # created by the "Run now" button
ACK_PATH = os.path.join(DATA_DIR, "ack.json")                # "done" marks set in the web UI: {issue id: {"ts": ...}}
WATCH_UNIT = "/etc/systemd/system/mailcow-reports-mail.path"  # inotify watch on the report mailbox
FOLDERS = ["INBOX", "Junk"]
UNPROCESSED = "Unprocessed"                                  # non-reports and broken reports are moved here
MAX_UNPACKED = 20 * 1024 * 1024                              # per attachment, guards against zip/gzip bombs
MAX_ROUNDS = 5                                               # re-check the mailbox for reports that arrived meanwhile
MAX_MSG_UNPACKED = 50 * 1024 * 1024                          # all attachments of one message together
MAX_ZIP_MEMBERS = 10
MAX_RECORDS = 20000                                          # DMARC records / TLS policies or failure details per report
MAX_ALERTS_PER_DAY = 10                                      # alert mails; fake reports must not flood the admins
MAX_PTR_LOOKUPS = 40                                         # new reverse-DNS lookups per export (rest: next run)
UNPROCESSED_KEEP_DAYS = 30                                   # parked mail older than this is deleted
DRY_RUN = "--dry-run" in sys.argv
DAY = 86400

LANG_DIRS = [os.path.join(COMPOSE_DIR, "data/web", WEB_SLUG, "lang"),     # installed next to the web page
             os.path.join(BASE, "..", "lang")]                            # source checkout (tests)


def load_lang(code):
    """Texts for a mailcow locale (de-de, en-gb, ...): exact file, else same base language, always on top of en-gb."""
    d = next((x for x in LANG_DIRS if os.path.isfile(os.path.join(x, "en-gb.json"))), None)
    if d is None:
        raise SystemExit("language files (lang/en-gb.json) not found")
    with open(os.path.join(d, "en-gb.json")) as f:
        texts = json.load(f)
    code = {"de": "de-de", "en": "en-gb"}.get(code, code)            # settings from version <= 0.3
    files = sorted(n[:-5] for n in os.listdir(d) if re.match(r"^[a-z]{2}-[a-z]{2}\.json$", n))
    pick = code if code in files else next((n for n in files if n[:2] == code[:2]), None)
    if pick and pick != "en-gb":
        with open(os.path.join(d, pick + ".json")) as f:
            texts.update({k: v for k, v in json.load(f).items() if isinstance(v, str) and v})
    return texts


T = load_lang(LANG)


def fmt(key, **p):
    """Text with {placeholders} filled in - tolerant of missing/extra placeholders in translations."""
    text = T.get(key, key)
    for k, v in p.items():
        text = text.replace("{" + k + "}", str(v))
    return text


def tr(item):
    """Render a text item {"k": key, "p": params} (see explain_items) in the alert language."""
    key = item["k"] if item["k"] in T else item.get("fb", item["k"])
    return fmt(key, **item.get("p", {})) + (f" ({item['c']})" if item.get("c") else "")


def mailcow_env():
    env = {}
    with open(os.path.join(COMPOSE_DIR, "mailcow.conf")) as f:
        for line in f:
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.rstrip("\n").split("=", 1)
                env[k.strip()] = v.strip()
    return env


def _public_ip(family, host):
    """Our public address as seen from outside - same service mailcow's DNS check uses."""
    try:
        addr = socket.getaddrinfo(host, 80, family, socket.SOCK_STREAM)[0][4]
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(addr)
            sock.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            resp = b""
            while len(resp) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
            head, _, body = resp.partition(b"\r\n\r\n")
            if head.split(b" ", 2)[1:2] != [b"200"]:
                return None
            body = body.decode(errors="replace").strip()
        ip = ipaddress.ip_address(body)
        return ip if ip.is_global else None
    except (OSError, ValueError):
        return None


def own_ips(con):
    """Manual list from the UI, or - like mailcow - SNAT_TO_SOURCE/SNAT6_TO_SOURCE from
    mailcow.conf, else the public addresses reported by ip4/ip6.mailcow.email.
    Auto mode remembers the last detected address per family, so a transient lookup failure
    never turns our own mail into "foreign" mail."""
    def valid(values):
        out = set()
        for a in values:
            try:
                out.add(ipaddress.ip_address(str(a).strip()))
            except ValueError:
                pass
        return out

    if OWN_IPS_MODE == "manual":
        return valid(CFG.get("own_ips", []))
    try:
        env = mailcow_env()
    except OSError:
        env = {}
    ips = set()
    for key, family, host in (("SNAT_TO_SOURCE", socket.AF_INET, "ip4.mailcow.email"),
                              ("SNAT6_TO_SOURCE", socket.AF_INET6, "ip6.mailcow.email")):
        fixed = valid([env.get(key, "")]) if env.get(key, "").strip() else set()
        ip = next(iter(fixed), None) or _public_ip(family, host)
        state_key = "own_ip_v4" if family == socket.AF_INET else "own_ip_v6"
        if ip:
            state_set(con, state_key, str(ip))
        else:
            ip = next(iter(valid([state_get(con, state_key, "")])), None)   # last known address
        if ip:
            ips.add(ip)
    ips = ips or valid(CFG.get("own_ips", []))
    # every address that was ever ours (provider changes) - used to classify stored rows
    history = set(json.loads(state_get(con, "own_ip_history", "[]")))
    history |= {str(i) for i in ips}
    state_set(con, "own_ip_history", json.dumps(sorted(history)))
    return ips | valid(history)


def configured_domains():
    """Domains from config, or all mailcow domains + alias domains ("auto")."""
    doms = CFG.get("domains", "auto")
    if isinstance(doms, list):
        return doms
    try:
        env = mailcow_env()
        sql = "SELECT domain FROM domain WHERE active=1 UNION SELECT alias_domain FROM alias_domain WHERE active=1 ORDER BY 1"
        r = subprocess.run(["docker", "compose", "exec", "-T", "mysql-mailcow", "mysql", "-N", "-u" + env["DBUSER"],
                            "-p" + env["DBPASS"], env["DBNAME"], "-e", sql], cwd=COMPOSE_DIR, capture_output=True,
                           input=b"", timeout=60)
        return [l.strip() for l in r.stdout.decode().splitlines() if l.strip()]
    except (OSError, KeyError, subprocess.SubprocessError):
        return []                                  # dashboard then lists the domains seen in reports


# --- mailbox

def doveadm(*args, input_bytes=None):
    cmd = ["docker", "compose", "exec", "-T", "dovecot-mailcow", "doveadm", *args]
    r = subprocess.run(cmd, cwd=COMPOSE_DIR, input=input_bytes if input_bytes is not None else b"",
                       capture_output=True, check=True, timeout=300)
    return r.stdout


def move_unprocessed(guid, uid):
    """Park a message in the Unprocessed folder (created on demand) so it is handled only once."""
    try:
        doveadm("mailbox", "create", "-u", MAILBOX, UNPROCESSED)
    except subprocess.CalledProcessError:
        pass                                       # already exists
    doveadm("move", "-u", MAILBOX, UNPROCESSED, "mailbox-guid", guid, "uid", uid)


def list_messages():
    # a mailbox created after dovecot cached a negative lookup would otherwise be "unknown"
    doveadm("auth", "cache", "flush")
    out = []
    for folder in FOLDERS:
        try:
            lines = doveadm("search", "-u", MAILBOX, "mailbox", folder, "ALL").decode().splitlines()
        except subprocess.CalledProcessError:
            continue                               # e.g. Junk not created yet
        for line in lines:
            parts = line.split()
            if len(parts) == 2:
                out.append((folder, parts[0], parts[1]))
    return out


def fetch(guid, uid):
    raw = doveadm("fetch", "-u", MAILBOX, "text", "mailbox-guid", guid, "uid", uid)
    raw = raw[len(b"text: "):] if raw.startswith(b"text: ") else raw
    return email.message_from_bytes(raw, policy=email.policy.default)


class TooLarge(ValueError):
    pass


def _gunzip(data):
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
        out = g.read(MAX_UNPACKED + 1)
    if len(out) > MAX_UNPACKED:
        raise TooLarge(f"gzip > {MAX_UNPACKED // 1048576} MB")
    return out


def payloads(msg):
    """(filename, bytes) of all report attachments, gz/zip unpacked with size limits."""
    total = 0
    for name, data in _payloads(msg):
        total += len(data)
        if total > MAX_MSG_UNPACKED:
            raise TooLarge(f"attachments > {MAX_MSG_UNPACKED // 1048576} MB")
        yield name, data


def _payloads(msg):
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = (part.get_filename() or "").lower()
        ctype = part.get_content_type()
        data = part.get_payload(decode=True)
        if not data:
            continue
        if name.endswith(".gz") or ctype in ("application/gzip", "application/x-gzip", "application/tlsrpt+gzip"):
            yield name[:-3], _gunzip(data)
        elif name.endswith(".zip") or ctype in ("application/zip", "application/x-zip-compressed"):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                if len(z.infolist()) > MAX_ZIP_MEMBERS:
                    raise TooLarge(f"zip with more than {MAX_ZIP_MEMBERS} files")
                for info in z.infolist():
                    if info.is_dir():
                        continue
                    if info.file_size > MAX_UNPACKED:
                        raise TooLarge(f"zip member > {MAX_UNPACKED // 1048576} MB")
                    with z.open(info) as f:
                        out = f.read(MAX_UNPACKED + 1)
                    if len(out) > MAX_UNPACKED:
                        raise TooLarge(f"zip member > {MAX_UNPACKED // 1048576} MB")
                    yield info.filename.lower(), out
        elif name.endswith((".xml", ".json")) or ctype in ("application/json", "application/tlsrpt+json", "text/xml", "application/xml"):
            if len(data) > MAX_UNPACKED:
                raise TooLarge(f"attachment > {MAX_UNPACKED // 1048576} MB")
            yield name, data


# --- database

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL, org TEXT, report_id TEXT, domain TEXT,
  policy TEXT, date_begin INTEGER, date_end INTEGER, received INTEGER,
  UNIQUE(kind, org, report_id, domain));
CREATE TABLE IF NOT EXISTS dmarc_rows (
  report INTEGER REFERENCES reports(id) ON DELETE CASCADE, source_ip TEXT, count INTEGER,
  disposition TEXT, dkim TEXT, spf TEXT, header_from TEXT, own INTEGER);
CREATE TABLE IF NOT EXISTS tls_rows (
  report INTEGER REFERENCES reports(id) ON DELETE CASCADE, domain TEXT, policy_type TEXT,
  ok INTEGER, fail INTEGER);
CREATE TABLE IF NOT EXISTS tls_fail (
  report INTEGER REFERENCES reports(id) ON DELETE CASCADE, result_type TEXT, count INTEGER,
  mx TEXT, sending_ip TEXT, receiving_ip TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS ptr_cache (ip TEXT PRIMARY KEY, ptr TEXT, checked INTEGER);
CREATE TABLE IF NOT EXISTS runs (ts INTEGER, reports INTEGER, alerts INTEGER, summary TEXT);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
"""


def db_open():
    con = sqlite3.connect(DB_PATH, timeout=60, isolation_level=None)   # explicit transactions below
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA journal_mode = WAL")
    con.executescript(SCHEMA)
    cols = {r[1] for r in con.execute("PRAGMA table_info(dmarc_rows)")}
    for col in ("envelope_from", "dkim_auth", "spf_auth", "reasons"):      # added in 0.2 (DMARC details)
        if col not in cols:
            con.execute(f"ALTER TABLE dmarc_rows ADD COLUMN {col} TEXT")
    return con


def state_get(con, key, default=None):
    row = con.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def state_set(con, key, value):
    con.execute("INSERT OR REPLACE INTO state VALUES (?,?)", (key, value))


def _s(v, n=255):
    """Report field → bounded plain string (reports are untrusted input)."""
    return "" if v is None else str(v).replace("\x00", "")[:n]


def insert_report(con, kind, org, report_id, domain, policy, begin, end, received):
    if con is None:
        return None
    org, report_id, domain, policy = _s(org, 200), _s(report_id, 300), _s(domain, 253), _s(policy, 40)
    cur = con.execute("INSERT OR IGNORE INTO reports(kind, org, report_id, domain, policy, date_begin, date_end, received)"
                      " VALUES (?,?,?,?,?,?,?,?)", (kind, org, report_id, domain, policy, begin, end, received))
    return cur.lastrowid if cur.rowcount else None   # None = duplicate, already stored


# --- parsing

def _ts(value):
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            return int(value)
        return int(datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp())
    except (ValueError, TypeError):
        return None


def parse_tlsrpt(data, findings, con, received):
    rep = json.loads(data)
    org = rep.get("organization-name", "?")
    rng = rep.get("date-range", {})
    begin, end = _ts(rng.get("start-datetime")), _ts(rng.get("end-datetime"))
    report_id = str(rep.get("report-id") or "")
    if not report_id or not isinstance(rep.get("policies"), list):
        raise ValueError("not a TLS-RPT report (report-id/policies missing)")
    if len(rep["policies"]) > MAX_RECORDS:
        raise TooLarge(f"more than {MAX_RECORDS} policies")
    for n, pol in enumerate(rep["policies"]):
        if not isinstance(pol, dict):
            raise ValueError("invalid policy entry")
        details = pol.get("failure-details") or []
        if not isinstance(details, list) or len(details) > MAX_RECORDS:
            raise ValueError("invalid failure-details")
        details = [d for d in details if isinstance(d, dict)]
        p = pol.get("policy", {})
        dom = str(p.get("policy-domain") or "?").lower().rstrip(".")
        s = pol.get("summary", {})
        ok, fail = int(s.get("total-successful-session-count", 0)), int(s.get("total-failure-session-count", 0))
        findings["tls_ok"] += ok
        # one row per policy: a report may contain several policies (sts, tlsa, ...) for one domain
        rid = insert_report(con, "tls", org, f"{report_id}#{n}", dom, p.get("policy-type"), begin, end, received)
        if rid:
            con.execute("INSERT INTO tls_rows VALUES (?,?,?,?,?)", (rid, dom, p.get("policy-type"), ok, fail))
            for d in details:
                con.execute("INSERT INTO tls_fail VALUES (?,?,?,?,?,?,?)", (
                    rid, _s(d.get("result-type"), 60), int(d.get("failed-session-count", 0)), _s(d.get("receiving-mx-hostname")),
                    _s(d.get("sending-mta-ip"), 45), _s(d.get("receiving-ip"), 45), _s(d.get("failure-reason-code"), 300)))
        if fail:
            details = "; ".join(
                f"{d.get('result-type')} ({d.get('failed-session-count')}x, MX {d.get('receiving-mx-hostname', '?')})"
                for d in details[:20]) or T["mail_no_details"]
            findings["alerts"].append(fmt("mail_tls", org=org, fail=fail, total=ok + fail, dom=dom, details=details))


FORWARD_REASONS = ("forwarded", "mailing_list", "trusted_forwarder")
# SQL: receiver flagged the row as forwarding (not spoofing)
FWD_SQL = "(" + " OR ".join(f"COALESCE(r.reasons, '') LIKE '%\"{x}\"%'" for x in FORWARD_REASONS) + ")"


def _aligned(d, hf):
    """Relaxed DMARC alignment (same domain or one is a subdomain of the other)."""
    d, hf = (d or "").lower().rstrip("."), (hf or "").lower().rstrip(".")
    return bool(d and hf) and (d == hf or d.endswith("." + hf) or hf.endswith("." + d))


def explain_items(ip, dkim, spf, hfrom, dkim_auth, spf_auth, reasons):
    """(cause key, text item) for a DMARC result, from auth_results and reasons.
    Text items are {"k": language key, "p": params}, rendered by the web page in the viewer's language."""
    out = []
    x = lambda cause, key, **p: out.append((cause, {"k": key, "p": p}))  # noqa: E731
    if dkim != "pass":
        good = [a for a in dkim_auth if a.get("result") == "pass"]
        bad = [a for a in dkim_auth if a.get("result") in ("fail", "neutral", "permerror", "policy")]
        temp = [a for a in dkim_auth if a.get("result") == "temperror"]
        if not dkim_auth or all(a.get("result") == "none" for a in dkim_auth):
            x("dkim_none", "x_dkim_none")
        for a in bad:
            x("dkim_bad", "x_dkim_bad", d=a.get("domain") or "?", s=a.get("selector") or "?", r=a.get("result"))
        for a in temp:
            x("temp", "x_dkim_temp", d=a.get("domain") or "?")
        n = len(out)
        for a in good:
            if not _aligned(a.get("domain"), hfrom):
                x("unaligned", "x_dkim_unaligned", d=a.get("domain"), hf=hfrom)
        if good and len(out) == n and not bad and not temp:   # valid + relaxed-aligned → strict adkim=s
            x("unaligned", "x_dkim_unaligned", d=good[0].get("domain"), hf=hfrom)
    if spf != "pass":
        n = len(out)
        if not spf_auth:
            x("spf_missing", "x_spf_missing")
        for a in spf_auth:
            r, d = a.get("result"), a.get("domain") or "?"
            if r == "pass" and not _aligned(d, hfrom):
                x("unaligned", "x_spf_unaligned", d=d, hf=hfrom)
            elif r in ("fail", "softfail", "neutral"):
                x("spf_fail", "x_spf_fail", ip=ip, d=d, r=r)
            elif r == "none":
                x("spf_dns", "x_spf_none", d=d)
            elif r == "permerror":
                x("spf_dns", "x_spf_perm", d=d)
            elif r == "temperror":
                x("temp", "x_spf_temp", d=d)
        if len(out) == n:                                      # passed + relaxed-aligned → strict aspf=s
            d = next((a.get("domain") for a in spf_auth if a.get("result") == "pass"), "?")
            x("unaligned", "x_spf_unaligned", d=d, hf=hfrom)
    for rs in reasons:
        typ = re.sub(r"[^a-z_]", "", str(rs.get("type") or "other").lower()) or "other"
        item = {"k": "x_reason_" + typ, "fb": "x_reason_other", "p": {}}
        if rs.get("comment"):
            item["c"] = str(rs["comment"])[:200]
        out.append(("forwarded" if typ in FORWARD_REASONS else "reason", item))
    return out


def explain(*args):
    return [t for _, t in explain_items(*args)]


def parse_dmarc(data, findings, con, received):
    # aggregate reports never need a DTD; refusing one rules out entity-expansion tricks altogether
    if isinstance(data, str):
        data = data.encode()
    if re.search(rb"<!\s*(DOCTYPE|ENTITY)", data, re.I):
        raise ValueError("XML with DOCTYPE/ENTITY declarations refused")
    root = ET.fromstring(data)
    for el in root.iter():                         # drop XML namespaces (DMARCbis, dmarc.org 0.1, ...)
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    if root.tag != "feedback":
        raise ValueError(f"not a DMARC report (<{root.tag}>)")
    org = (root.findtext("report_metadata/org_name") or "?").strip()
    report_id = (root.findtext("report_metadata/report_id") or "").strip()
    if not report_id:
        raise ValueError("DMARC report without report_id")
    begin = _ts(root.findtext("report_metadata/date_range/begin", ""))
    end = _ts(root.findtext("report_metadata/date_range/end", ""))
    dom = (root.findtext("policy_published/domain") or "?").strip().lower().rstrip(".")
    policy = root.findtext("policy_published/p", "")
    rid = insert_report(con, "dmarc", org, report_id, dom, policy, begin, end, received)
    records = root.findall("record")
    if len(records) > MAX_RECORDS:
        raise TooLarge(f"more than {MAX_RECORDS} records")
    for rec in records:
        ip = rec.findtext("row/source_ip", "").strip()
        cnt = int((rec.findtext("row/count") or "0").strip())
        dkim = rec.findtext("row/policy_evaluated/dkim", "")
        spf = rec.findtext("row/policy_evaluated/spf", "")
        disp = rec.findtext("row/policy_evaluated/disposition", "")
        hfrom = (rec.findtext("identifiers/header_from") or dom).strip().lower()
        env_from = (rec.findtext("identifiers/envelope_from") or "").strip().lower()
        dkim_auth = [{"domain": (a.findtext("domain") or "").strip().lower(), "selector": (a.findtext("selector") or "").strip(),
                      "result": (a.findtext("result") or "").strip().lower()} for a in rec.findall("auth_results/dkim")]
        spf_auth = [{"domain": (a.findtext("domain") or "").strip().lower(), "scope": (a.findtext("scope") or "").strip().lower(),
                     "result": (a.findtext("result") or "").strip().lower()} for a in rec.findall("auth_results/spf")]
        reasons = [{"type": (r.findtext("type") or "").strip().lower(), "comment": (r.findtext("comment") or "").strip()[:200]}
                   for r in rec.findall("row/policy_evaluated/reason")]
        try:
            own = ipaddress.ip_address(ip) in OWN_IPS
        except ValueError:
            own = False
        passed = "pass" in (dkim, spf)
        if rid:
            con.execute("INSERT INTO dmarc_rows (report, source_ip, count, disposition, dkim, spf, header_from, own,"
                        " envelope_from, dkim_auth, spf_auth, reasons) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (rid, ip, cnt, disp, dkim, spf, hfrom, int(own), env_from,
                         json.dumps(dkim_auth), json.dumps(spf_auth), json.dumps(reasons)))
        if own:
            findings["dmarc_own_ok" if passed else "dmarc_own_fail"] += cnt
            if not passed:
                why = explain(ip, dkim, spf, hfrom, dkim_auth, spf_auth, reasons)
                findings["alerts"].append(fmt("mail_dmarc", org=org, cnt=cnt, ip=ip, dom=dom, dkim=dkim, spf=spf)
                                          + ("".join(f"\n    {T['mail_why']}: {tr(w)}" for w in why) if why else ""))
        elif not passed and not any(r["type"] in FORWARD_REASONS for r in reasons):
            findings["spoof"][dom] = findings["spoof"].get(dom, 0) + cnt


def send_alert(findings):
    """Deliver the alert into every ALERT_TO mailbox. Never raises; returns the recipients that failed."""
    body = [T["mail_intro"], ""] + [f"- {a}" for a in findings["alerts"]]
    body += ["", fmt("mail_summary", reports=findings["reports"], tls_ok=findings["tls_ok"],
                                     ok=findings["dmarc_own_ok"], fail=findings["dmarc_own_fail"])]
    if findings["spoof"]:
        body += ["", T["mail_spoof"]] + [f"- {d}: {n}" for d, n in sorted(findings["spoof"].items())]
    body += [""]
    if PUBLIC_URL:
        body += [fmt("mail_details", url=PUBLIC_URL)]
    body += [fmt("mail_kept", box=MAILBOX, folder=UNPROCESSED), f"-- mailcow-report-dashboard @ {socket.gethostname()}"]
    m = EmailMessage()
    m["From"] = f"{T['mail_sender']} <{MAILBOX}>"
    m["To"] = ", ".join(ALERT_TO)
    m["Subject"] = T["mail_subject"]
    m["Date"] = formatdate(localtime=True)
    m["Message-ID"] = make_msgid(domain=MAILBOX.split("@")[-1])
    m.set_content("\n".join(body))
    if DRY_RUN:
        print(m)
        return []
    failed = []
    for rcpt in ALERT_TO:
        try:   # delivered straight into the INBOX - no SMTP, no spam filter, no DKIM needed
            doveadm("save", "-u", rcpt, "-m", "INBOX", input_bytes=m.as_bytes())
        except (subprocess.SubprocessError, OSError) as e:
            failed.append(f"{rcpt}: {type(e).__name__}")
    return failed


# --- export

_ptr_budget = [MAX_PTR_LOOKUPS]


def ptr(con, ip):
    row = con.execute("SELECT ptr, checked FROM ptr_cache WHERE ip=?", (ip,)).fetchone()
    if row and row[1] > time.time() - 30 * DAY:
        return row[0]
    if _ptr_budget[0] <= 0:              # many new foreign IPs: resolve the rest on the next run
        return row[0] if row else ""
    _ptr_budget[0] -= 1
    try:
        socket.setdefaulttimeout(3)
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        name = ""
    con.execute("INSERT OR REPLACE INTO ptr_cache VALUES (?,?,?)", (ip, name, int(time.time())))
    return name


def _run_info(row):
    ts, reports, alerts, summary = row
    try:
        stats = json.loads(summary)
    except (TypeError, ValueError):
        stats = {}
    return {"ts": ts, "reports": reports, "alerts": alerts, "stats": stats if isinstance(stats, dict) else {}}


def export(con):
    now = int(time.time())
    since30, since90, since365 = now - 30 * DAY, now - 90 * DAY, now - 365 * DAY
    q = lambda sql, *a: con.execute(sql, a).fetchall()  # noqa: E731

    # domains (last 30 days)
    domains = []
    domains_cfg = configured_domains()
    seen = [r[0] for r in q("SELECT DISTINCT domain FROM reports WHERE date_end>=?", since365)]
    for d in domains_cfg + [s for s in seen if s not in domains_cfg]:
        own = q("SELECT COALESCE(SUM(CASE WHEN r.dkim='pass' OR r.spf='pass' THEN r.count END),0),"
                " COALESCE(SUM(CASE WHEN NOT(r.dkim='pass' OR r.spf='pass') THEN r.count END),0)"
                " FROM dmarc_rows r JOIN reports p ON p.id=r.report WHERE p.domain=? AND p.date_end>=? AND r.own=1", d, since30)[0]
        foreign = q("SELECT COALESCE(SUM(r.count),0) FROM dmarc_rows r JOIN reports p ON p.id=r.report"
                    " WHERE p.domain=? AND p.date_end>=? AND r.own=0 AND NOT(r.dkim='pass' OR r.spf='pass') AND NOT " + FWD_SQL, d, since30)[0][0]
        tls = q("SELECT COALESCE(SUM(t.ok),0), COALESCE(SUM(t.fail),0) FROM tls_rows t JOIN reports p ON p.id=t.report"
                " WHERE t.domain=? AND p.date_end>=?", d, since30)[0]
        last = q("SELECT MAX(date_end) FROM reports WHERE domain=?", d)[0][0]
        policy = q("SELECT policy FROM reports WHERE domain=? AND kind='dmarc' ORDER BY date_end DESC LIMIT 1", d)
        days = q("SELECT COUNT(DISTINCT date_end/86400) FROM reports WHERE domain=? AND kind='dmarc' AND date_end>=?", d, since30)[0][0]
        reporters = q("SELECT COUNT(DISTINCT org) FROM reports WHERE domain=? AND date_end>=?", d, since30)[0][0]
        if not last:
            status, note = "grey", "no_reports"
        elif own[1] or tls[1]:
            status, note = "red", "errors"
        elif own[0] == 0:
            status, note = "green", "receive_only"
        else:
            status, note = "green", "ok"
        policy = policy[0][0] if policy else ""
        ready = bool(last) and own[1] == 0 and tls[1] == 0 and days >= 21 and policy != "reject"
        domains.append(dict(domain=d, status=status, note=note, own_pass=own[0], own_fail=own[1], spoof=foreign,
                            tls_ok=tls[0], tls_fail=tls[1], last=last, policy=policy, days=days,
                            reporters=reporters, reject_ready=ready, configured=d in domains_cfg))

    # weekly series (52 weeks)
    weeks = defaultdict(lambda: dict(own_pass=0, own_fail=0, spoof=0, tls_ok=0, tls_fail=0))
    for wk, ok, bad, spoof in q("SELECT (p.date_end+259200)/604800, SUM(CASE WHEN r.own=1 AND (r.dkim='pass' OR r.spf='pass') THEN r.count ELSE 0 END),"
                                " SUM(CASE WHEN r.own=1 AND NOT(r.dkim='pass' OR r.spf='pass') THEN r.count ELSE 0 END),"
                                " SUM(CASE WHEN r.own=0 AND NOT(r.dkim='pass' OR r.spf='pass') AND NOT " + FWD_SQL + " THEN r.count ELSE 0 END)"
                                " FROM dmarc_rows r JOIN reports p ON p.id=r.report WHERE p.date_end>=? GROUP BY 1", since365):
        weeks[wk].update(own_pass=ok, own_fail=bad, spoof=spoof)
    for wk, ok, bad in q("SELECT (p.date_end+259200)/604800, SUM(t.ok), SUM(t.fail) FROM tls_rows t JOIN reports p ON p.id=t.report"
                         " WHERE p.date_end>=? GROUP BY 1", since365):
        weeks[wk].update(tls_ok=ok, tls_fail=bad)
    cur = (now + 259200) // 604800                 # weeks starting on Monday
    series = [dict(week=(cur - i) * 604800 - 259200, **weeks[cur - i]) for i in range(51, -1, -1)]

    reporters = []
    for org, n in q("SELECT org, COUNT(*) FROM reports WHERE date_end>=? GROUP BY org ORDER BY 2 DESC", since30):
        own_ok, own_bad, dmarc_n = q("SELECT COALESCE(SUM(CASE WHEN r.own=1 AND (r.dkim='pass' OR r.spf='pass') THEN r.count END),0),"
                                     " COALESCE(SUM(CASE WHEN r.own=1 AND NOT(r.dkim='pass' OR r.spf='pass') THEN r.count END),0),"
                                     " COUNT(DISTINCT p.id) FROM reports p LEFT JOIN dmarc_rows r ON r.report=p.id"
                                     " WHERE p.org=? AND p.kind='dmarc' AND p.date_end>=?", org, since30)[0]
        tls_ok, tls_bad, tls_n = q("SELECT COALESCE(SUM(t.ok),0), COALESCE(SUM(t.fail),0), COUNT(DISTINCT p.id)"
                                   " FROM reports p LEFT JOIN tls_rows t ON t.report=p.id WHERE p.org=? AND p.kind='tls' AND p.date_end>=?",
                                   org, since30)[0]
        reporters.append(dict(org=org, own_pass=own_ok, own_fail=own_bad, dmarc_reports=dmarc_n,
                              tls_ok=tls_ok, tls_fail=tls_bad, tls_reports=tls_n, reports=n))

    spoof = []
    for ip, cnt, doms, first, last, disp in q(
            "SELECT r.source_ip, SUM(r.count), GROUP_CONCAT(DISTINCT p.domain), MIN(p.date_begin), MAX(p.date_end),"
            " GROUP_CONCAT(DISTINCT r.disposition) FROM dmarc_rows r JOIN reports p ON p.id=r.report"
            " WHERE r.own=0 AND NOT(r.dkim='pass' OR r.spf='pass') AND NOT " + FWD_SQL + " AND p.date_end>=? GROUP BY r.source_ip"
            " ORDER BY 2 DESC LIMIT 100", since90):
        spoof.append(dict(ip=ip, ptr=ptr(con, ip), count=cnt, domains=sorted(set((doms or "").split(","))),
                          first=first, last=last, disposition=disp))

    # foreign senders that PASS DMARC (e.g. a newsletter service) - informational
    other_pass = [dict(ip=ip, ptr=ptr(con, ip), count=cnt, domains=sorted(set((doms or "").split(","))))
                  for ip, cnt, doms in q("SELECT r.source_ip, SUM(r.count), GROUP_CONCAT(DISTINCT p.domain)"
                                         " FROM dmarc_rows r JOIN reports p ON p.id=r.report WHERE r.own=0"
                                         " AND (r.dkim='pass' OR r.spf='pass') AND p.date_end>=? GROUP BY 1 ORDER BY 2 DESC LIMIT 30", since90)]
    # forwarded / mailing-list copies of our mail that failed DMARC - usually harmless
    forwarded = [dict(ip=ip, ptr=ptr(con, ip), count=cnt, domains=sorted(set((doms or "").split(","))),
                      reasons=sorted({x.get("type") for rs in (reas or "").split("\x1f") for x in _j(rs)} - {None, ""}))
                 for ip, cnt, doms, reas in q("SELECT r.source_ip, SUM(r.count), GROUP_CONCAT(DISTINCT p.domain),"
                                              " GROUP_CONCAT(r.reasons, char(31)) FROM dmarc_rows r JOIN reports p ON p.id=r.report"
                                              " WHERE r.own=0 AND NOT(r.dkim='pass' OR r.spf='pass') AND " + FWD_SQL +
                                              " AND p.date_end>=? GROUP BY 1 ORDER BY 2 DESC LIMIT 30", since90)]

    # own mail that failed DMARC, grouped by cause (90 days)
    causes = defaultdict(lambda: dict(count=0, first=None, last=None, orgs=set(), domains=set(), ips=set()))
    for ip, cnt, dk, sp, hf, da, sa, rs, org, dom, b, e in q(
            "SELECT r.source_ip, r.count, r.dkim, r.spf, r.header_from, r.dkim_auth, r.spf_auth, r.reasons, p.org, p.domain,"
            " p.date_begin, p.date_end FROM dmarc_rows r JOIN reports p ON p.id=r.report"
            " WHERE r.own=1 AND NOT(r.dkim='pass' OR r.spf='pass') AND p.date_end>=?", since90):
        why = explain(ip, dk, sp, hf, _j(da), _j(sa), _j(rs)) or [{"k": "x_unknown"}]
        c = causes[json.dumps(why, sort_keys=True)]
        c["count"] += cnt
        c["first"] = min(x for x in (c["first"], b) if x) if (c["first"] or b) else None
        c["last"] = max(x for x in (c["last"], e) if x) if (c["last"] or e) else None
        c["orgs"].add(org); c["domains"].add(dom); c["ips"].add(ip)
    own_fail_causes = sorted(({"why": json.loads(k), "count": v["count"], "first": v["first"], "last": v["last"],
                               "orgs": sorted(v["orgs"]), "domains": sorted(v["domains"]), "ips": sorted(v["ips"])}
                              for k, v in causes.items()), key=lambda x: -x["count"])

    # ---- plain-language overview (last 30 days). Every issue has a stable id; when it is marked as
    # done in the UI only reports that arrived afterwards count, so it comes back only for new cases.
    ack = _acks()
    open_since = lambda iid, rcv: rcv is not None and rcv > ack.get(iid, 0)  # noqa: E731
    issues = []
    own_total, own_ok = q("SELECT COALESCE(SUM(r.count),0), COALESCE(SUM(CASE WHEN r.dkim='pass' OR r.spf='pass' THEN r.count END),0)"
                          " FROM dmarc_rows r JOIN reports p ON p.id=r.report WHERE r.own=1 AND p.date_end>=?", since30)[0]
    groups = defaultdict(lambda: dict(count=0, first=None, last=None))

    def add(iid, cnt, rcv):
        g = groups[iid]
        g["count"] += cnt
        g["first"] = min(rcv, g["first"] or rcv)
        g["last"] = max(rcv, g["last"] or rcv)

    for ip, cnt, dk, sp, hf, da, sa, rs, rcv in q(
            "SELECT r.source_ip, r.count, r.dkim, r.spf, r.header_from, r.dkim_auth, r.spf_auth, r.reasons, p.received"
            " FROM dmarc_rows r JOIN reports p ON p.id=r.report WHERE r.own=1 AND NOT(r.dkim='pass' OR r.spf='pass')"
            " AND p.date_end>=?", since30):
        keys = [k for k, _ in explain_items(ip, dk, sp, hf, _j(da), _j(sa), _j(rs))]
        key = next((k for k in ("dkim_none", "dkim_bad", "spf_fail", "spf_dns", "unaligned", "temp") if k in keys), "other")
        if open_since("own:" + key, rcv):
            add("own:" + key, cnt, rcv)
    for rt, cnt, rcv in q("SELECT f.result_type, f.count, p.received FROM tls_fail f JOIN reports p ON p.id=f.report"
                          " WHERE p.date_end>=?", since30):
        if open_since(f"tls:{rt}", rcv):
            add(f"tls:{rt}", cnt, rcv)
    for cnt, rcv, fwd in q("SELECT r.count, p.received, " + FWD_SQL + " FROM dmarc_rows r JOIN reports p ON p.id=r.report"
                           " WHERE r.own=0 AND NOT(r.dkim='pass' OR r.spf='pass') AND p.date_end>=?", since30):
        iid = "fwd" if fwd else "spoof"
        if open_since(iid, rcv):
            add(iid, cnt, rcv)
    for iid, g in groups.items():
        kind, _, key = iid.partition(":")
        # texts are language keys; the web page renders them in the viewer's language
        if kind == "own":
            t = "i_" + key
            text = dict(title=t + "_t", what=t + "_w", todo=t + "_d")
            sev = "info" if key == "temp" else ("error" if own_total and g["count"] / own_total > 0.05 else "warn")
        elif kind == "tls":
            r = "tlsr_" + key if "tlsr_" + key + "_w" in T else "tlsr_other"
            text = dict(title="i_tls_t", what=r + "_w", todo=r + "_d")
            sev = "error"
        else:
            text = dict(title=f"i_{iid}_t", what=f"i_{iid}_w", todo=f"i_{iid}_d")
            sev = "ok"
        issues.append(dict(id=iid, severity=sev, text=text, p=dict(n=g["count"], r=key),
                           count=g["count"], first=g["first"], last=g["last"]))
    order = {"error": 0, "warn": 1, "info": 2, "ok": 3}
    issues.sort(key=lambda x: (order[x["severity"]], -x["count"]))
    tls_total, tls_bad = q("SELECT COALESCE(SUM(t.ok)+SUM(t.fail),0), COALESCE(SUM(t.fail),0) FROM tls_rows t"
                           " JOIN reports p ON p.id=t.report WHERE p.date_end>=?", since30)[0]
    spoofed = sum(x["spoof"] for x in domains)
    fwd_n = q("SELECT COALESCE(SUM(r.count),0) FROM dmarc_rows r JOIN reports p ON p.id=r.report WHERE r.own=0"
              " AND NOT(r.dkim='pass' OR r.spf='pass') AND " + FWD_SQL + " AND p.date_end>=?", since30)[0][0]
    kpi = dict(own_total=own_total, own_ok=own_ok, own_pct=round(100 * own_ok / own_total, 1) if own_total else None,
               tls_total=tls_total, tls_bad=tls_bad, tls_pct=round(100 * (tls_total - tls_bad) / tls_total, 1) if tls_total else None,
               spoofed=spoofed, forwarded=fwd_n, reports30=q("SELECT COUNT(*) FROM reports WHERE date_end>=?", since30)[0][0])

    tls_failures = [dict(when=w, org=o, domain=d, result=rt, count=c, mx=mx, ip=ip, reason=rs) for w, o, d, rt, c, mx, ip, rs in q(
        "SELECT p.date_end, p.org, p.domain, f.result_type, f.count, f.mx, f.sending_ip, f.reason FROM tls_fail f"
        " JOIN reports p ON p.id=f.report WHERE p.date_end>=? ORDER BY p.date_end DESC LIMIT 100", since90)]

    recent = []
    for rid, kind, org, dom, policy, b, e, rcv in q("SELECT id, kind, org, domain, policy, date_begin, date_end, received"
                                                    " FROM reports ORDER BY received DESC, id DESC LIMIT 60"):
        if kind == "dmarc":
            rows = [dict(ip=ip, count=c, disposition=di, dkim=dk, spf=sp, own=bool(ow),
                         fwd=any(x.get("type") in FORWARD_REASONS for x in _j(rs)),
                         why=explain(ip, dk, sp, hf, _j(da), _j(sa), _j(rs)) if not (dk == "pass" or sp == "pass") or _j(rs) else [])
                    for ip, c, di, dk, sp, ow, hf, da, sa, rs in q(
                        "SELECT source_ip, count, disposition, dkim, spf, own, header_from, dkim_auth, spf_auth, reasons"
                        " FROM dmarc_rows WHERE report=? ORDER BY count DESC", rid)]
            passed = lambda r: "pass" in (r["dkim"], r["spf"])  # noqa: E731
            stats = dict(total=sum(r["count"] for r in rows),
                         own_ok=sum(r["count"] for r in rows if r["own"] and passed(r)),
                         own_fail=sum(r["count"] for r in rows if r["own"] and not passed(r)),
                         spoof=sum(r["count"] for r in rows if not r["own"] and not passed(r) and not r["fwd"]))
            problem = stats["own_fail"] > 0
        else:
            rows = [dict(ok=o, fail=f, policy=pt) for o, f, pt in q("SELECT ok, fail, policy_type FROM tls_rows WHERE report=?", rid)]
            stats = dict(tls_ok=sum(r["ok"] for r in rows), tls_fail=sum(r["fail"] for r in rows))
            problem = stats["tls_fail"] > 0
        recent.append(dict(kind=kind, org=org, domain=dom, policy=policy, begin=b, end=e, received=rcv,
                           stats=stats, problem=problem, rows=rows))

    last_run = q("SELECT ts, reports, alerts, summary FROM runs ORDER BY ts DESC LIMIT 1")
    totals = q("SELECT COUNT(*), MIN(date_begin) FROM reports")[0]
    data = dict(generated=now, last_run=_run_info(last_run[0]) if last_run else None,
                last_daily=int(state_get(con, "last_daily", "0") or 0), unprocessed=int(state_get(con, "unprocessed", "0") or 0),
                alert_error=state_get(con, "alert_error", ""),
                total_reports=totals[0], since=totals[1], domains=domains, series=series, reporters=reporters,
                spoof=spoof, other_pass=other_pass, forwarded=forwarded, tls_failures=tls_failures, own_fail_causes=own_fail_causes, issues=issues, kpi=kpi, recent=recent, retention_days=RETENTION_DAYS,
                language=LANG, run_time=RUN_TIME, mailbox=MAILBOX, alert_to=", ".join(ALERT_TO), own_ips=sorted(str(i) for i in OWN_IPS), own_ips_mode=OWN_IPS_MODE)
    write_atomic(EXPORT_PATH, json.dumps(data, ensure_ascii=False))


def _acks():
    """ack.json from the web UI → {issue id: timestamp}; anything malformed is ignored."""
    try:
        raw = read_untrusted_json(ACK_PATH)
    except (OSError, ValueError):
        return {}
    out = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            ts = v.get("ts") if isinstance(v, dict) else v
            if isinstance(k, str) and isinstance(ts, (int, float)):
                out[k] = int(ts)
    return out


def _j(value):
    try:
        v = json.loads(value) if value else []
        return v if isinstance(v, list) else []
    except (TypeError, ValueError):
        return []


def write_atomic(path, text, mode=0o644):
    """Write via a fresh random temp file (O_EXCL, never follows a planted symlink) + rename.
    DATA_DIR is writable by the web server, so plain open(path + '.tmp', 'w') would be unsafe."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            os.fchmod(f.fileno(), mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --- main

def mailbox_dirs():
    """Maildir 'new' folders of the report mailbox (INBOX + Junk) inside the vmail volume."""
    if not MAILBOX:
        return []
    r = subprocess.run(["docker", "volume", "ls", "-q"], capture_output=True, text=True)
    vol = next((v for v in r.stdout.split() if v.endswith("vmail-vol-1")), None)
    if not vol:
        return []
    mp = subprocess.run(["docker", "volume", "inspect", "-f", "{{.Mountpoint}}", vol], capture_output=True, text=True).stdout.strip()
    local, domain = MAILBOX.split("@", 1)          # MAILBOX is validated against ADDR_RE
    base = os.path.join(mp, domain, local, "Maildir")
    if "\n" in base or not base.startswith("/"):
        return []
    return [os.path.join(base, "new"), os.path.join(base, ".Junk", "new")]


def ensure_watch():
    """Keep mailcow-reports-mail.path pointing at the configured mailbox (changes in the UI)."""
    dirs = mailbox_dirs()
    body = ("[Unit]\nDescription=mailcow report dashboard - process new reports as soon as they arrive\n\n[Path]\n"
            + "".join(f"PathChanged={d}\n" for d in dirs)
            + "Unit=mailcow-reports-mail.service\nTriggerLimitIntervalSec=60\nTriggerLimitBurst=20\n\n"
              "[Install]\nWantedBy=paths.target\n")
    try:
        with open(WATCH_UNIT) as f:
            if f.read() == body:
                return
    except FileNotFoundError:
        pass
    if not dirs:
        return
    write_atomic(WATCH_UNIT, body)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "enable", "--now", "mailcow-reports-mail.path"], check=False, capture_output=True)
    subprocess.run(["systemctl", "restart", "mailcow-reports-mail.path"], check=False)


def due(con):
    """--scheduled: run when "run now" was requested, or once a day after RUN_TIME."""
    if os.path.lexists(RUN_NOW_FLAG):
        os.remove(RUN_NOW_FLAG)
        return True
    try:
        hh, mm = (int(x) for x in RUN_TIME.split(":"))
    except ValueError:
        hh, mm = 7, 30
    now = datetime.now()
    if (now.hour, now.minute) < (hh, mm):
        return False
    # instant runs (new mail) don't count - the safety net must run once every day
    last = int(state_get(con, "last_daily", "0") or 0)
    if last and datetime.fromtimestamp(last).date() >= now.date():
        return False
    state_set(con, "last_daily", str(int(time.time())))
    return True


def process_message(con, guid, uid):
    """Parse one message inside its own savepoint: stored completely or not at all.
    Returns ("report", findings) or ("foreign", None); raises on broken reports."""
    msg = fetch(guid, uid)
    try:
        received = int(parsedate_to_datetime(msg.get("date")).timestamp())
    except (TypeError, ValueError, IndexError):
        received = int(time.time())
    f = {"alerts": [], "tls_ok": 0, "dmarc_own_ok": 0, "dmarc_own_fail": 0, "spoof": {}}
    handled = False
    db = None if DRY_RUN else con
    if db:
        db.execute("SAVEPOINT msg")
    try:
        for name, data in payloads(msg):
            head = data.lstrip()[:1]
            if name.endswith(".json") or head == b"{":
                parse_tlsrpt(data, f, db, received); handled = True
            elif name.endswith(".xml") or head == b"<":
                parse_dmarc(data, f, db, received); handled = True
    except Exception:
        if db:
            db.execute("ROLLBACK TO msg")
            db.execute("RELEASE msg")
        raise
    if db:
        db.execute("RELEASE msg")
    return ("report", f) if handled else ("foreign", None)


def reclassify(con):
    """Mark rows from any of our (current or former) addresses as own, everything else as foreign."""
    for (ip,) in con.execute("SELECT DISTINCT source_ip FROM dmarc_rows").fetchall():
        try:
            own = int(ipaddress.ip_address(ip) in OWN_IPS)
        except ValueError:
            own = 0
        con.execute("UPDATE dmarc_rows SET own=? WHERE source_ip=? AND own<>?", (own, ip, own))


def _safe(fn, *args):
    try:
        return fn(*args)
    except (subprocess.SubprocessError, OSError) as e:
        print(f"warning: {getattr(fn, '__name__', fn)}: {e}", file=sys.stderr)
        return None


def _header(guid, uid, name):
    try:
        out = doveadm("fetch", "-u", MAILBOX, f"hdr.{name}", "mailbox-guid", guid, "uid", uid).decode(errors="replace")
        return " ".join(out.split(":", 1)[-1].split())[:120]
    except (subprocess.SubprocessError, OSError):
        return "?"


def _count(folder):
    try:
        out = doveadm("mailbox", "status", "-u", MAILBOX, "messages", folder).decode()
        return int(out.strip().split("=")[-1])
    except (subprocess.SubprocessError, OSError, ValueError):
        return 0


def main():
    global OWN_IPS
    # one run at a time (daily timer, "run now" and new-mail trigger may coincide)
    lock = open(DB_PATH + ".lock", "w")
    fcntl.flock(lock, fcntl.LOCK_EX)
    con = db_open()
    if not DRY_RUN and os.geteuid() == 0:
        try:
            ensure_watch()
        except (OSError, subprocess.SubprocessError) as e:
            print(f"warning: could not update the new-mail watch: {e}", file=sys.stderr)
    con.execute("BEGIN")
    go = "--scheduled" not in sys.argv or due(con)
    con.execute("COMMIT")
    if not go:
        return                                     # hourly check, nothing due: no network, no work
    con.execute("BEGIN")
    OWN_IPS = own_ips(con)
    reclassify(con)
    con.execute("COMMIT")
    if "--export-only" in sys.argv or not MAILBOX:
        con.execute("BEGIN")
        if not MAILBOX and "--export-only" not in sys.argv:
            con.execute("INSERT INTO runs VALUES (?,?,?,?)", (int(time.time()), 0, 0, json.dumps({"no_mailbox": True})))
        export(con)
        con.execute("COMMIT")
        return

    findings = {"alerts": [], "tls_ok": 0, "dmarc_own_ok": 0, "dmarc_own_fail": 0, "spoof": {}, "reports": 0, "foreign": 0}
    seen = set()
    for _ in range(MAX_ROUNDS):                    # reports that arrive during a run are picked up too
        todo = [m for m in list_messages() if (m[1], m[2]) not in seen]
        if not todo:
            break
        for folder, guid, uid in todo:
            seen.add((guid, uid))
            con.execute("BEGIN")
            try:
                kind, res = process_message(con, guid, uid)
                con.execute("COMMIT")              # stored first, then removed from the mailbox
            except Exception as e:  # noqa: BLE001 - broken report: park it, alert once
                con.execute("COMMIT")              # (its savepoint was rolled back)
                findings["alerts"].append(fmt("mail_unreadable", 
                    subject=_header(guid, uid, "subject"), sender=_header(guid, uid, "from"),
                    err=f"{type(e).__name__}: {e}"[:200], box=MAILBOX, folder=UNPROCESSED))
                if not DRY_RUN:
                    _safe(move_unprocessed, guid, uid)
                continue
            if kind == "report":
                findings["reports"] += 1
                for k in ("tls_ok", "dmarc_own_ok", "dmarc_own_fail"):
                    findings[k] += res[k]
                findings["alerts"] += res["alerts"]
                for d, n in res["spoof"].items():
                    findings["spoof"][d] = findings["spoof"].get(d, 0) + n
                if not DRY_RUN:
                    _safe(doveadm, "expunge", "-u", MAILBOX, "mailbox-guid", guid, "uid", uid)
            else:                                  # spam/foreign mail in the report box: park silently
                findings["foreign"] += 1
                if not DRY_RUN:
                    _safe(move_unprocessed, guid, uid)

    alert_failed = []
    if findings["alerts"] and ALERT_TO and not DRY_RUN:
        day, sent = (state_get(con, "alerts_day", "") or ":0").split(":")
        sent = int(sent) if day == f"{datetime.now():%Y-%m-%d}" else 0
        if sent < MAX_ALERTS_PER_DAY:      # anyone can mail fake reports - never flood the admins
            alert_failed = send_alert(findings)
            con.execute("BEGIN")
            state_set(con, "alerts_day", f"{datetime.now():%Y-%m-%d}:{sent + 1}")
            con.execute("COMMIT")
        else:
            print(f"alert limit ({MAX_ALERTS_PER_DAY}/day) reached - details on the dashboard", file=sys.stderr)
    summary = json.dumps({"reports": findings["reports"], "tls_ok": findings["tls_ok"], "own_ok": findings["dmarc_own_ok"],
                          "own_fail": findings["dmarc_own_fail"], "spoofed": sum(findings["spoof"].values()),
                          "alerts": len(findings["alerts"]), "foreign": findings["foreign"], "alert_failed": alert_failed})
    print(f"{datetime.now():%Y-%m-%d %H:%M} {summary}")
    if DRY_RUN:
        return
    con.execute("BEGIN")
    if _count(UNPROCESSED):                        # folder exists and has mail: drop what is older than 30 days
        _safe(doveadm, "expunge", "-u", MAILBOX, "mailbox", UNPROCESSED, "savedbefore", f"{UNPROCESSED_KEEP_DAYS}d")
    state_set(con, "unprocessed", str(_count(UNPROCESSED)))
    state_set(con, "alert_error", ", ".join(alert_failed))
    con.execute("DELETE FROM reports WHERE COALESCE(date_end, received) < ?", (int(time.time()) - RETENTION_DAYS * DAY,))
    con.execute("DELETE FROM runs WHERE ts < ?", (int(time.time()) - RETENTION_DAYS * DAY,))
    con.execute("INSERT INTO runs VALUES (?,?,?,?)", (int(time.time()), findings["reports"], len(findings["alerts"]), summary))
    export(con)
    con.execute("COMMIT")


if __name__ == "__main__":
    main()

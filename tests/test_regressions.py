import json
import gzip
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import run
from collector import mailcow_reports as collector


def findings():
    return {"alerts": [], "tls_ok": 0, "dmarc_own_ok": 0, "dmarc_own_fail": 0, "spoof": {}}


def dmarc_xml(report_id="report-1", count=3):
    return f"""<feedback>
      <report_metadata><org_name>Receiver</org_name><report_id>{report_id}</report_id>
        <date_range><begin>1761955200</begin><end>1762041600</end></date_range>
      </report_metadata>
      <policy_published><domain>example.org</domain><p>reject</p></policy_published>
      <record><row><source_ip>192.0.2.1</source_ip><count>{count}</count>
        <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
      </row><identifiers><header_from>example.org</header_from></identifiers><auth_results/></record>
    </feedback>"""


class CollectorRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = str(pathlib.Path(self.temp.name) / "reports.db")
        self.db_patch = patch.object(collector, "DB_PATH", self.db_path)
        self.ip_patch = patch.object(collector, "OWN_IPS", {collector.ipaddress.ip_address("192.0.2.1")})
        self.db_patch.start()
        self.ip_patch.start()
        self.db = collector.db_open()

    def tearDown(self):
        self.db.close()
        self.ip_patch.stop()
        self.db_patch.stop()
        self.temp.cleanup()

    def test_duplicate_dmarc_report_has_no_second_findings(self):
        first = findings()
        second = findings()
        collector.parse_dmarc(dmarc_xml(), first, self.db, 1762041700)
        collector.parse_dmarc(dmarc_xml(), second, self.db, 1762041700)

        self.assertEqual(first["dmarc_own_fail"], 3)
        self.assertEqual(len(first["alerts"]), 1)
        self.assertEqual(second["dmarc_own_fail"], 0)
        self.assertEqual(second["alerts"], [])
        self.assertEqual(self.db.execute("SELECT count(*) FROM reports").fetchone()[0], 1)

    def test_duplicate_tls_report_has_no_second_findings(self):
        report = json.dumps({
            "organization-name": "Receiver",
            "report-id": "tls-1",
            "date-range": {"start-datetime": 1761955200, "end-datetime": 1762041600},
            "policies": [{
                "policy": {"policy-type": "sts", "policy-domain": "example.org"},
                "summary": {"total-successful-session-count": 2, "total-failure-session-count": 1},
            }],
        })
        first = findings()
        second = findings()
        collector.parse_tlsrpt(report, first, self.db, 1762041700)
        collector.parse_tlsrpt(report, second, self.db, 1762041700)

        self.assertEqual(first["tls_ok"], 2)
        self.assertEqual(len(first["alerts"]), 1)
        self.assertEqual(second["tls_ok"], 0)
        self.assertEqual(second["alerts"], [])

        dry_run = findings()
        collector.parse_tlsrpt(report, dry_run, None, 1762041700)
        self.assertEqual(dry_run["tls_ok"], 2)
        self.assertEqual(len(dry_run["alerts"]), 1)

    def test_tls_failure_detail_limit_applies_to_the_whole_report(self):
        policy = {
            "policy": {"policy-type": "sts", "policy-domain": "example.org"},
            "summary": {"total-successful-session-count": 0, "total-failure-session-count": 2},
            "failure-details": [{"failed-session-count": 1}, {"failed-session-count": 1}],
        }
        report = json.dumps({
            "organization-name": "Receiver",
            "report-id": "detail-limit",
            "policies": [policy, policy],
        })
        with patch.object(collector, "MAX_RECORDS", 3):
            with self.assertRaisesRegex(collector.TooLarge, "failure details"):
                collector.parse_tlsrpt(report, findings(), self.db, 1762041700)

    def test_negative_counts_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "negative DMARC row count"):
            collector.parse_dmarc(dmarc_xml("negative", -1), findings(), self.db, 1762041700)

    def test_dmarc_xml_with_doctype_is_rejected(self):
        report = '<!DOCTYPE feedback [<!ENTITY x "expanded">]><feedback>&x;</feedback>'
        with self.assertRaisesRegex(ValueError, "DOCTYPE/ENTITY"):
            collector.parse_dmarc(report, findings(), self.db, 1762041700)

    def test_gzip_unpacked_limit_is_enforced(self):
        with patch.object(collector, "MAX_UNPACKED", 10):
            with self.assertRaises(collector.TooLarge):
                collector._gunzip(gzip.compress(b"x" * 11))

    def test_daily_trigger_is_not_marked_complete_by_due(self):
        flag = str(pathlib.Path(self.temp.name) / "run-now")
        with patch.object(collector, "RUN_NOW_FLAG", flag), patch.object(collector, "RUN_TIME", "00:00"):
            self.assertEqual(collector.due(self.db), "daily")
            self.assertIsNone(collector.state_get(self.db, "last_daily"))
            self.assertIsNone(collector.due(self.db))          # failed attempt: wait DAILY_RETRY, not every check
            collector.state_set(self.db, "daily_retry_after", "0")
            self.assertEqual(collector.due(self.db), "daily")

    def test_daily_trigger_without_mailbox_is_done_for_the_day(self):
        flag = str(pathlib.Path(self.temp.name) / "run-now")
        with patch.object(collector, "RUN_NOW_FLAG", flag), patch.object(collector, "RUN_TIME", "00:00"), \
                patch.object(collector, "MAILBOX", ""), patch.object(collector, "own_ips", return_value=set()), \
                patch.object(collector, "reclassify"), patch.object(collector, "export"), \
                patch.object(collector.sys, "argv", ["mailcow_reports.py", "--scheduled"]):
            collector.main()
            with collector.db_open() as db:
                self.assertIsNotNone(collector.state_get(db, "last_daily"))
                self.assertIsNone(collector.due(db))

    def test_daily_trigger_is_completed_only_after_successful_run(self):
        flag = str(pathlib.Path(self.temp.name) / "run-now")
        common = (
            patch.object(collector, "RUN_NOW_FLAG", flag),
            patch.object(collector, "RUN_TIME", "00:00"),
            patch.object(collector, "MAILBOX", "reports@example.org"),
            patch.object(collector, "DRY_RUN", False),
            patch.object(collector, "own_ips", return_value=set()),
            patch.object(collector, "reclassify"),
            patch.object(collector, "list_messages", return_value=[]),
            patch.object(collector, "_count", return_value=0),
            patch.object(collector, "export"),
            patch.object(collector.sys, "argv", ["mailcow_reports.py", "--scheduled"]),
        )
        with common[0], common[1], common[2], common[3], common[4], common[5], common[6], common[7], common[8], common[9], \
                patch.object(collector, "imap", return_value=object()):
            collector.main()
        with collector.db_open() as db:
            self.assertIsNotNone(collector.state_get(db, "last_daily"))

        os.unlink(self.db_path)
        with patch.object(collector, "RUN_NOW_FLAG", flag), patch.object(collector, "RUN_TIME", "00:00"), \
                patch.object(collector, "MAILBOX", "reports@example.org"), patch.object(collector, "DRY_RUN", False), \
                patch.object(collector, "own_ips", return_value=set()), patch.object(collector, "reclassify"), \
                patch.object(collector, "export"), patch.object(collector.sys, "argv", ["mailcow_reports.py", "--scheduled"]), \
                patch.object(collector, "imap", side_effect=OSError("offline")):
            collector.main()
        with collector.db_open() as db:
            self.assertIsNone(collector.state_get(db, "last_daily"))


class EntrypointRegressionTests(unittest.TestCase):
    def test_atomic_copy_does_not_follow_predictable_temp_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            source, target, victim = base / "source", base / "target", base / "victim"
            source.write_text("new")
            victim.write_text("safe")
            os.symlink(victim, str(target) + ".tmp")

            run.copy_if_changed(str(source), str(target))

            self.assertEqual(target.read_text(), "new")
            self.assertEqual(victim.read_text(), "safe")

    def test_web_writable_json_reader_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            victim, link = base / "victim.json", base / "credentials.json"
            victim.write_text('{"user":"secret","password":"secret"}')
            os.symlink(victim, link)

            with self.assertRaises(OSError):
                run.read_untrusted_json(str(link))

    def test_collector_timeout_is_contained(self):
        with patch.object(run.subprocess, "run", side_effect=subprocess.TimeoutExpired("collector", 1800)), \
                patch.object(run, "log") as log:
            self.assertFalse(run.run_collector("--scheduled"))
        log.assert_called_once_with("collector timed out after 1800 seconds")

    def test_poller_refreshes_selected_mailbox_before_status(self):
        class Idle:
            def __enter__(self):
                return iter(())

            def __exit__(self, *args):
                return False

        class Imap:
            def __init__(self, *args, **kwargs):
                self.refreshed = False

            def login(self, *args):
                pass

            def noop(self):
                self.refreshed = True

            def status(self, *args):
                if not self.refreshed:
                    raise AssertionError("STATUS used stale selected-mailbox state")
                return "OK", [b"(MESSAGES 0)"]

            def select(self, *args, **kwargs):
                return "OK", []

            def idle(self, **kwargs):
                return Idle()

        poller = run.Poller()
        with patch.object(run, "read_untrusted_json", return_value={"user": "reports@example.org", "password": "pw"}), \
                patch.object(run, "_IMAP", Imap):
            self.assertFalse(poller.wait_for_mail(1))
        self.assertTrue(poller.conn.refreshed)


if __name__ == "__main__":
    unittest.main()

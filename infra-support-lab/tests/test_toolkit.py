from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import zipfile

from infra_support.cli import create_backup, demo, load_config, main, probe, run_checks, write_report


@contextmanager
def tcp_server():
    with socketserver.TCPServer(("127.0.0.1", 0), socketserver.BaseRequestHandler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            worker.join()


class ToolkitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "file.txt").write_text("important data: привет", encoding="utf-8")
        self.archive = self.root / "backup.zip"

    def backup_check(self):
        return {"name": "Backup", "type": "backup", "path": str(self.archive), "max_age_hours": 24}

    def config(self, checks):
        path = self.root / "config.json"
        path.write_text(json.dumps({"checks": checks}), encoding="utf-8")
        return path

    def test_backup_roundtrip_preserves_bytes(self):
        (self.source / "nested").mkdir()
        (self.source / "nested" / "binary.bin").write_bytes(bytes(range(256)))
        create_backup(self.source, self.archive)
        restored = self.root / "restored"
        with zipfile.ZipFile(self.archive) as archive:
            archive.extractall(restored)
        for file in self.source.rglob("*"):
            if file.is_file():
                self.assertEqual(file.read_bytes(), (restored / file.relative_to(self.source)).read_bytes())
        self.assertEqual(run_checks([self.backup_check()])["status"], "OK")

    def test_backup_will_not_overwrite(self):
        self.archive.write_bytes(b"existing archive")
        with self.assertRaises(ValueError):
            create_backup(self.source, self.archive)
        self.assertEqual(self.archive.read_bytes(), b"existing archive")

    def test_backup_inside_source_rejected(self):
        with self.assertRaises(ValueError):
            create_backup(self.source, self.source / "backup.zip")

    def test_empty_source_rejected(self):
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaises(ValueError):
            create_backup(empty, self.archive)

    def test_stale_backup_fails(self):
        create_backup(self.source, self.archive)
        old = time.time() - 48 * 3600
        os.utime(self.archive, (old, old))
        self.assertEqual(run_checks([self.backup_check()])["status"], "FAIL")

    def test_future_timestamp_fails(self):
        create_backup(self.source, self.archive)
        future = time.time() + 3600
        os.utime(self.archive, (future, future))
        self.assertEqual(run_checks([self.backup_check()])["status"], "FAIL")

    def test_missing_backup_fails_without_crash(self):
        self.assertEqual(run_checks([self.backup_check()])["summary"]["failed"], 1)

    def test_corrupt_backup_fails(self):
        self.archive.write_bytes(b"not a zip")
        self.assertEqual(run_checks([self.backup_check()])["status"], "FAIL")

    def test_empty_zip_fails(self):
        with zipfile.ZipFile(self.archive, "w"):
            pass
        self.assertEqual(run_checks([self.backup_check()])["status"], "FAIL")

    def test_tcp_accepts_connection(self):
        with tcp_server() as port:
            report = run_checks([{"name": "TCP", "type": "tcp", "host": "127.0.0.1", "port": port}])
        self.assertEqual(report["status"], "OK")

    def test_tcp_refused_is_failure(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            report = run_checks([{"name": "TCP", "type": "tcp", "host": "127.0.0.1",
                                  "port": reserved.getsockname()[1], "timeout": 0.1}])
        self.assertEqual(report["status"], "FAIL")

    def test_dns_localhost(self):
        self.assertEqual(run_checks([{"name": "DNS", "type": "dns", "host": "localhost"}])["status"], "OK")

    def test_dns_failure_does_not_stop_other_checks(self):
        with patch("infra_support.cli.socket.getaddrinfo", side_effect=socket.gaierror("failed")):
            report = run_checks([{"name": "DNS", "type": "dns", "host": "example.invalid"},
                                 {"name": "Disk", "type": "disk", "path": str(self.root), "min_free_percent": 0.001}])
        self.assertEqual(report["summary"], {"total": 2, "ok": 1, "failed": 1})

    def test_low_disk_space(self):
        with patch("infra_support.cli.shutil.disk_usage", return_value=type("Usage", (), {"total": 100, "free": 5})()):
            self.assertEqual(run_checks([{"name": "Disk", "type": "disk", "path": ".", "min_free_percent": 10}])["status"], "FAIL")

    def test_paths_relative_to_config_not_working_directory(self):
        checks = load_config(self.config([{"name": "Disk", "type": "disk", "path": "source", "min_free_percent": 5}]))
        self.assertEqual(checks[0]["path"], str(self.source.resolve()))

    def test_bad_configuration_rejected(self):
        invalid = [
            [], [{"name": "X", "type": "unknown"}],
            [{"name": "X", "type": "dns", "host": "localhost", "typo": True}],
            [{"name": "X", "type": "tcp", "host": "localhost", "port": True}],
            [{"name": "X", "type": "tcp", "host": "localhost", "port": 65536}],
            [{"name": "X", "type": "tcp", "host": "localhost", "port": 80, "timeout": -1}],
            [{"name": "X", "type": "disk", "path": ".", "min_free_percent": float("nan")}],
            [{"name": "X", "type": "dns", "host": ""}],
            [{"name": "X", "type": "dns", "host": "localhost"}] * 2,
        ]
        for checks in invalid:
            with self.subTest(checks=checks), self.assertRaises(ValueError):
                load_config(self.config(checks))

    def test_missing_sqlcmd_fails(self):
        with patch("infra_support.cli.shutil.which", return_value=None):
            report = run_checks([{"name": "SQL", "type": "mssql", "server": "localhost"}])
        self.assertEqual(report["status"], "FAIL")

    def test_sql_command_and_success(self):
        with patch("infra_support.cli.shutil.which", return_value="sqlcmd"), patch(
            "infra_support.cli.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "1\n", "")
        ) as run:
            self.assertIn("succeeded", probe({"type": "mssql", "server": "localhost"}))
        args = run.call_args.args[0]
        self.assertIn("-E", args)
        self.assertIn("-b", args)
        self.assertNotIn("-C", args)
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    def test_sql_failure_does_not_leak_output(self):
        with patch("infra_support.cli.shutil.which", return_value="sqlcmd"), patch(
            "infra_support.cli.subprocess.run", return_value=subprocess.CompletedProcess([], 1, "", "private details")
        ):
            report = run_checks([{"name": "SQL", "type": "mssql", "server": "localhost"}])
        self.assertEqual(report["status"], "FAIL")
        self.assertNotIn("private details", json.dumps(report))

    def test_sql_timeout_is_failure(self):
        with patch("infra_support.cli.shutil.which", return_value="sqlcmd"), patch(
            "infra_support.cli.subprocess.run", side_effect=subprocess.TimeoutExpired("sqlcmd", 5)
        ):
            self.assertEqual(run_checks([{"name": "SQL", "type": "mssql", "server": "localhost"}])["status"], "FAIL")

    def test_sql_password_not_in_arguments(self):
        with patch.dict(os.environ, {"SQLCMDPASSWORD": "secret"}), patch(
            "infra_support.cli.shutil.which", return_value="sqlcmd"
        ), patch("infra_support.cli.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "1", "")) as run:
            probe({"type": "mssql", "server": "localhost", "username": "reader"})
        self.assertNotIn("secret", run.call_args.args[0])
        self.assertNotIn("-P", run.call_args.args[0])
        self.assertNotIn("-E", run.call_args.args[0])

    def test_html_escapes_names_and_messages(self):
        report = run_checks([{"name": "<script>alert(1)</script>", "type": "disk", "path": str(self.root), "min_free_percent": 0.001}])
        write_report(report, self.root)
        page = (self.root / "report.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertEqual(json.loads((self.root / "report.json").read_text(encoding="utf-8")), report)

    def test_cli_exit_codes(self):
        path = self.config([{"name": "Disk", "type": "disk", "path": ".", "min_free_percent": 0.001}])
        self.assertEqual(main(["check", "--config", str(path), "--output", str(self.root / "reports")]), 0)
        path = self.config([self.backup_check()])
        self.assertEqual(main(["check", "--config", str(path), "--output", str(self.root / "reports")]), 1)
        path.write_text("{invalid", encoding="utf-8")
        self.assertEqual(main(["check", "--config", str(path)]), 2)

    def test_demo_emits_real_success_and_failure(self):
        self.assertEqual(demo(self.root / "reports"), 0)
        healthy = json.loads((self.root / "reports/healthy.json").read_text(encoding="utf-8"))
        incident = json.loads((self.root / "reports/incident.json").read_text(encoding="utf-8"))
        self.assertEqual(healthy["summary"]["ok"], 4)
        self.assertEqual(incident["summary"]["failed"], 1)
        self.assertIn("stale", incident["checks"][-1]["message"])


if __name__ == "__main__":
    unittest.main()

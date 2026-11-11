"""Read-only service checks and verified file backups. Python 3.10+."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import html
import json
import math
import os
from pathlib import Path
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import zipfile
import zlib


def positive(value, label, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number")
    if not math.isfinite(value) or value <= 0 or (maximum and value > maximum):
        raise ValueError(f"{label} is outside its allowed range")
    return value


def load_config(path):
    path = Path(path).resolve()
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"checks"}:
        raise ValueError("Config must contain only 'checks'")
    checks = data["checks"]
    if not isinstance(checks, list) or not 1 <= len(checks) <= 100:
        raise ValueError("Expected 1..100 checks")
    fields = {
        "dns": ({"host"}, set()),
        "tcp": ({"host", "port"}, {"timeout"}),
        "disk": ({"path", "min_free_percent"}, set()),
        "backup": ({"path", "max_age_hours"}, set()),
        "mssql": ({"server"}, {"timeout", "username"}),
    }
    names = set()
    for check in checks:
        if not isinstance(check, dict):
            raise ValueError("Each check must be an object")
        name, kind = check.get("name"), check.get("type")
        if not isinstance(name, str) or not name.strip() or name in names:
            raise ValueError("Check names must be non-empty and unique")
        names.add(name)
        if not isinstance(kind, str) or kind not in fields:
            raise ValueError(f"Unknown check type: {kind}")
        required, optional = fields[kind]
        keys = set(check) - {"name", "type"}
        if not required <= keys or keys - required - optional:
            raise ValueError(f"Invalid fields for {name}")
        for key in ("host", "server", "username", "path"):
            if key in check and (not isinstance(check[key], str) or not check[key].strip()):
                raise ValueError(f"{name}.{key} must be non-empty text")
        if "port" in check:
            port = check["port"]
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise ValueError("Port must be an integer in 1..65535")
        if "timeout" in check:
            positive(check["timeout"], "timeout", 30)
        if kind == "disk":
            positive(check["min_free_percent"], "min_free_percent", 100)
        if kind == "backup":
            positive(check["max_age_hours"], "max_age_hours")
        if "path" in check:
            check["path"] = str((path.parent / check["path"]).resolve())
    return checks


def probe(check):
    kind = check["type"]
    if kind == "dns":
        # System resolver policy controls DNS timeouts, not socket.settimeout().
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(check["host"], None)})
        if not addresses:
            raise OSError("Resolver returned no addresses")
        return ", ".join(addresses)
    if kind == "tcp":
        with socket.create_connection((check["host"], check["port"]), check.get("timeout", 3)):
            return "TCP connection accepted (application health not verified)"
    if kind == "disk":
        usage = shutil.disk_usage(check["path"])
        free = usage.free / usage.total * 100
        if free < check["min_free_percent"]:
            raise OSError(f"Free disk space {free:.1f}% is below threshold")
        return f"Free disk space: {free:.1f}%"
    if kind == "backup":
        path = Path(check["path"])
        age = (time.time() - path.stat().st_mtime) / 3600
        if age < -0.02:
            raise OSError("Backup timestamp is in the future; check host clock")
        if age > check["max_age_hours"]:
            raise OSError(f"Backup is stale: {age:.1f} hours")
        with zipfile.ZipFile(path) as archive:
            if not any(not member.is_dir() for member in archive.infolist()):
                raise OSError("Backup contains no files")
            if archive.testzip() is not None:
                raise OSError("Backup CRC verification failed")
        return f"Backup age: {max(age, 0):.2f} hours; ZIP CRC verified"
    if kind == "mssql":
        executable = shutil.which("sqlcmd")
        if not executable:
            raise OSError("sqlcmd not found; install Microsoft command-line tools")
        timeout = max(1, math.ceil(check.get("timeout", 5)))
        command = [executable, "-S", check["server"], "-b", "-l", str(timeout),
                   "-t", str(timeout), "-Q", "SET NOCOUNT ON; SELECT 1;", "-h", "-1", "-W"]
        if "username" in check:
            if not os.environ.get("SQLCMDPASSWORD"):
                raise OSError("SQLCMDPASSWORD environment variable is required")
            command += ["-U", check["username"]]
        else:
            command += ["-E"]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout * 2 + 2)
        if completed.returncode != 0 or completed.stdout.strip() != "1":
            # Never include raw sqlcmd output or environment in published reports.
            raise OSError(f"SQL SELECT 1 failed (sqlcmd exit {completed.returncode})")
        return "SQL SELECT 1 succeeded"
    raise ValueError(f"Unknown check type: {kind}")


def run_checks(checks):
    results = []
    for check in checks:
        start = time.monotonic()
        try:
            message = probe(check)
            status = "OK"
        except (OSError, ValueError, zipfile.BadZipFile, zlib.error, EOFError, RuntimeError, subprocess.SubprocessError) as exc:
            status, message = "FAIL", str(exc)
        results.append({"name": check["name"], "type": check["type"], "status": status,
                        "message": message, "duration_ms": round((time.monotonic() - start) * 1000, 2)})
    counts = Counter(row["status"] for row in results)
    return {"schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": "FAIL" if counts["FAIL"] else "OK",
            "summary": {"total": len(results), "ok": counts["OK"], "failed": counts["FAIL"]},
            "checks": results}


def write_report(report, output, stem="report"):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / f"{stem}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    esc = lambda value: html.escape(str(value), quote=True)
    rows = "".join(f'<tr><td>{esc(r["name"])}</td><td>{esc(r["type"])}</td>'
                   f'<td class="{esc(r["status"])}">{esc(r["status"])}</td>'
                   f'<td>{esc(r["message"])}</td><td>{r["duration_ms"]}</td></tr>' for r in report["checks"])
    page = f'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Infra Support Lab</title>
<style>body{{font:16px system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;color:#172339;background:#f4f7fb}}
h1{{font-size:32px}}table{{border-collapse:collapse;width:100%;background:white}}td,th{{padding:14px;text-align:left;border-bottom:1px solid #d9e1eb;overflow-wrap:anywhere}}
.OK{{color:#137344;font-weight:bold}}.FAIL{{color:#b02727;font-weight:bold}}.wrap{{overflow-x:auto}}p{{line-height:1.6}}</style>
<h1>Infra Support Lab</h1><p>Status: <b class="{esc(report['status'])}">{esc(report['status'])}</b><br>
UTC: {esc(report['generated_at'])}<br>{report['summary']['ok']} passed / {report['summary']['failed']} failed</p>
<div class="wrap"><table><thead><tr><th>Check</th><th>Type</th><th>Status</th><th>Details</th><th>ms</th></tr></thead><tbody>{rows}</tbody></table></div>
<p>TCP availability does not prove application health. ZIP CRC does not prove recoverability of a running database.</p></html>'''
    (output / f"{stem}.html").write_text(page, encoding="utf-8")


def create_backup(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if not source.is_dir():
        raise ValueError("Backup source must be a directory")
    if destination == source or source in destination.parents:
        raise ValueError("Backup destination must be outside the source directory")
    if destination.exists():
        raise ValueError("Destination already exists; use a new archive name")
    files = []
    for entry in source.rglob("*"):
        if entry.is_symlink() or (hasattr(entry, "is_junction") and entry.is_junction()):
            raise ValueError("Symlinks and junctions are not supported")
        if entry.is_file():
            files.append(entry)
    if not files:
        raise ValueError("Source contains no files")
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix="backup-", suffix=".tmp", dir=destination.parent)
    os.close(handle)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for file in sorted(files):
                archive.write(file, file.relative_to(source))
        with zipfile.ZipFile(temporary) as archive:
            if archive.testzip() is not None:
                raise OSError("Backup verification failed")
        # Exclusive creation protects an existing archive, including concurrent invocations.
        with destination.open("xb") as target, open(temporary, "rb") as stream:
            try:
                shutil.copyfileobj(stream, target)
            except BaseException:
                target.close()
                destination.unlink(missing_ok=True)
                raise
    finally:
        Path(temporary).unlink(missing_ok=True)
    return destination


def demo(output):
    """Bind only loopback; no external network or installed services required."""
    with tempfile.TemporaryDirectory(prefix="infra-demo-") as temporary:
        root = Path(temporary)
        source = root / "files"
        source.mkdir()
        (source / "example.txt").write_text("Demo file server data\n", encoding="utf-8")
        archive = create_backup(source, root / "backup.zip")
        with socketserver.TCPServer(("127.0.0.1", 0), socketserver.BaseRequestHandler) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                checks = [
                    {"name": "Local DNS resolver", "type": "dns", "host": "localhost"},
                    {"name": "Demo TCP service", "type": "tcp", "host": "127.0.0.1", "port": server.server_address[1]},
                    {"name": "Disk free space", "type": "disk", "path": str(root), "min_free_percent": 0.001},
                    {"name": "File backup", "type": "backup", "path": str(archive), "max_age_hours": 24},
                ]
                healthy = run_checks(checks)
                write_report(healthy, output, "healthy")
                old = time.time() - 48 * 3600
                os.utime(archive, (old, old))
                incident = run_checks(checks)
                write_report(incident, output, "incident")
            finally:
                server.shutdown()
                worker.join()
        print(f"Healthy: {healthy['status']}; stale-backup incident: {incident['status']}")
        print(f"Reports: {Path(output).resolve()}")
        return 0 if healthy["status"] == "OK" and incident["summary"]["failed"] == 1 else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="Check configured services; exit 1 on any failure")
    check.add_argument("--config", required=True)
    check.add_argument("--output", default="reports")
    backup = sub.add_parser("backup", help="Create and CRC-verify a ZIP of ordinary files")
    backup.add_argument("--source", required=True)
    backup.add_argument("--destination", required=True)
    sample = sub.add_parser("demo", help="Local healthy + incident scenarios")
    sample.add_argument("--output", default="reports/demo")
    args = parser.parse_args(argv)
    try:
        if args.command == "backup":
            print(create_backup(args.source, args.destination))
            return 0
        if args.command == "demo":
            return demo(args.output)
        report = run_checks(load_config(args.config))
        write_report(report, args.output)
        print(json.dumps(report["summary"]))
        return 0 if report["status"] == "OK" else 1
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"Configuration or file error: {exc}", file=__import__('sys').stderr)
        return 2

#!/usr/bin/env bash
# Read-only Ubuntu diagnostics. Output can contain private host/network details.
set -euo pipefail
printf '=== OS ===\n'
uname -a
if [[ -r /etc/os-release ]]; then cat /etc/os-release; fi
printf '\n=== Disk ===\n'
df -h
printf '\n=== Network ===\n'
if command -v ip >/dev/null 2>&1; then ip -brief address; ip route; fi
printf '\n=== Resolver ===\n'
if command -v resolvectl >/dev/null 2>&1; then
    resolvectl status || true
elif [[ -r /etc/resolv.conf ]]; then
    cat /etc/resolv.conf
fi
printf '\n=== Failed services ===\n'
if command -v systemctl >/dev/null 2>&1; then systemctl --failed --no-pager || true; fi
printf '\n=== Listening TCP sockets ===\n'
if command -v ss >/dev/null 2>&1; then ss -ltn; fi

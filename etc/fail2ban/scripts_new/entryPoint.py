#!/usr/bin/env python3
# /etc/fail2ban/scripts/entryPoint.py
import argparse
import os
import subprocess
import sys

parser = argparse.ArgumentParser(
    description="""
Fail2Ban Cloudflare List Sync Entry Point

This script sets up a virtual environment (if needed) and runs cloudflare_sync.py to sync Fail2Ban bans to a Cloudflare WAF IP list.

It is typically invoked automatically by Fail2Ban actions (via cloudflare-list-new.conf) on ban/unban/start/stop events.

Manual usage is supported for testing or manual sync.

Usage: entryPoint.py <action> [arguments]

Available actions:
  ban <ip> [jail]     Add IP to Cloudflare list. <ip> is required, <jail> optional (e.g., 'sshd').
                      Triggered on Fail2Ban ban events; also works for manual ban restore (skips DB check).

  del <ip>            Remove IP from Cloudflare list.
                      Triggered on Fail2Ban unban events.

  start               Sync all active bans from Fail2Ban DB to Cloudflare list (bulk operation).
                      Run on Fail2Ban start (if enabled) or manually for full resync.

  stop                Remove all IPs from Cloudflare list (bulk unban).
                      Run on Fail2Ban stop.

Every scenario:
- Automatic ban: Fail2Ban -> action -> entryPoint.py ban <ip> <jail>
- Automatic unban: Fail2Ban -> action -> entryPoint.py del <ip>
- Startup sync: Fail2Ban start -> action -> entryPoint.py start (if ENABLE_START_SYNC=true in auth.sh)
- Shutdown clear: Fail2Ban stop -> action -> entryPoint.py stop
- Manual ban test: ./entryPoint.py ban 1.2.3.4 test-jail
- Manual unban: ./entryPoint.py del 1.2.3.4
- Manual sync: ./entryPoint.py start

Environment: Sources cloudflare_auth.sh for CF_TOKEN, ACCOUNT_ID, LIST_ID, etc.
Logs to /var/log/fail2ban-cloudflare-list.log.
Supports IPv4/IPv6 (/64 truncation), retries, caching, bulk ops for efficiency.

See .clinerules/brief.md for full project details.
    """,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    add_help=True
)

subparsers = parser.add_subparsers(dest='action', required=True, help='Available actions')

# ban subparser
ban_parser = subparsers.add_parser('ban', help='Add IP to Cloudflare list (ban)')
ban_parser.add_argument('ip', help='IP address to ban (IPv4 or IPv6)')
ban_parser.add_argument('jail', nargs='?', default='', help='Jail name (optional, e.g., "sshd")')

# del subparser
del_parser = subparsers.add_parser('del', help='Remove IP from Cloudflare list (unban)')
del_parser.add_argument('ip', help='IP address to unban (IPv4 or IPv6)')

# start subparser
start_parser = subparsers.add_parser('start', help='Sync all active Fail2Ban bans to Cloudflare list (manual or startup)')

# stop subparser
stop_parser = subparsers.add_parser('stop', help='Clear all IPs from Cloudflare list (shutdown)')

# flush_cf subparser (manual bulk clear)
flush_cf_parser = subparsers.add_parser('flush_cf', help='Manual: Flush (clear) entire Cloudflare list')

# flush_cache subparser
flush_cache_parser = subparsers.add_parser('flush_cache', help='Manual: Clear local CF cache file')

# local_info subparser
local_info_parser = subparsers.add_parser('local_info', help='Manual: Query local Fail2Ban DB bans')
local_info_sub = local_info_parser.add_subparsers(dest='subaction', help='Local info subactions')
local_total = local_info_sub.add_parser('total', help='Show total active bans')
local_count = local_info_sub.add_parser('count', help='Show count of active bans (same as total)')
local_list = local_info_sub.add_parser('list', help='List all active banned IPs with details')
local_query = local_info_sub.add_parser('query', help='Query specific IP')
local_query.add_argument('ip', help='IP to query (IPv4 or IPv6)')

# compare subparser
compare_parser = subparsers.add_parser('compare', help='Manual: Compare local bans vs CF list')
compare_parser.add_argument('--force', action='store_true', help='Force refresh CF list (invalidate cache)')

args = parser.parse_args()

# Path to venv relative to this script
script_dir = os.path.dirname(os.path.abspath(__file__))
venv_path = os.path.join(script_dir, '.venv')

# Create venv if it doesn't exist
if not os.path.exists(venv_path):
    print("Creating virtual environment...", file=sys.stderr)
    subprocess.check_call([sys.executable, '-m', 'venv', venv_path])
    # Install dependencies in venv
    pip_path = os.path.join(venv_path, 'bin', 'pip')
    subprocess.check_call([pip_path, 'install', 'requests', 'tenacity'])

import shutil

# Clean __pycache__ to force reload updated .py files
pycache_dir = os.path.join(script_dir, '__pycache__')
if os.path.exists(pycache_dir):
    shutil.rmtree(pycache_dir)
    print("Cleared __pycache__ for updated code", file=sys.stderr)

# Use venv Python to run the core script
python_exe = os.path.join(venv_path, 'bin', 'python')
core_script = os.path.join(script_dir, 'cloudflare_sync.py')

# Execute with original args (e.g., 'ban 1.2.3.4 sshd')
subprocess.check_call([python_exe, core_script] + sys.argv[1:])

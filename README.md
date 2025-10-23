# Fail2Ban to Cloudflare IP Sync

## Project Overview
Custom Fail2Ban integration with Cloudflare WAF Rules lists (free). Bans from jails sync to CF custom IP list via API (`{BASE_URL}/accounts/{CF_ACCOUNT_ID}/rules/lists/{CF_LIST_ID}/items`), blocking at edge. Supports IPv6 /64 truncation.

### Key Technologies
- Python 3.6+
- Libraries: requests, tenacity, ipaddress, sqlite3
- Tools: Fail2Ban, Cloudflare API (WAF Rules Lists endpoint)
- Environment: Linux (e.g., Ubuntu), Fail2Ban installed

### High-Level Architecture
- Jails monitor logs (nginx, sshd, wordpress, etc.).
- Bans trigger action in cloudflare-list-new.conf: sources cloudflare_auth.sh (sets env/creds), runs entryPoint.py (venv setup, deps install), invokes cloudflare_sync.py (normalize IP, query Fail2Ban DB, API add/del with retry/pagination/log, bulk operations for efficiency, caching for repeated fetches).
- DB: `/var/lib/fail2ban/fail2ban.sqlite3` for active bans.
- Logs: `/var/log/fail2ban-cloudflare-list.log`
- Configs via auth.sh (hardcoded; insecure—consider env vars).

## Getting Started

### Prerequisites
- Fail2Ban installed.
- Python 3.6+.
- Cloudflare: API token (scopes: Account.Rules:Edit + Read), account ID, existing WAF list (ID above).
- Root access for `/etc/fail2ban/`.

### Installation
1. Copy files:
   - scripts_new/ to `/etc/fail2ban/scripts_new/` (entryPoint.py, cloudflare_sync.py, cloudflare_auth.sh).
   - action.d/cloudflare-list-new.conf to `/etc/fail2ban/action.d/`.
   - jail.d/*.conf to `/etc/fail2ban/jail.d/` (update actions to cloudflare-list-new).
   - `chmod +x /etc/fail2ban/scripts_new/*.py *.sh`

2. Secure creds: Edit cloudflare_auth.sh—remove hardcoded token/ID (use env vars in production).

3. Test: `/etc/fail2ban/scripts_new/entryPoint.py ban 1.2.3.4 test` (ensure venv creates, API works).

4. Enable: In jail.local, enable custom jails. Restart: `sudo systemctl restart fail2ban`.

### Basic Usage
- Monitor: `sudo fail2ban-client status <jail>`
- Manual ban: `sudo fail2ban-client set <jail> banip <ip>` (triggers sync)
- View CF list: Cloudflare dashboard > Security > WAF > Custom rules > IP Access Rules (or API GET)
- Manual actions (via entryPoint.py): ban `<ip>` [jail], del `<ip>`, start (sync), stop (bulk clear), flush_cf (bulk clear), flush_cache (clear cache), local_info [total|count|list|query `<ip>`] (DB query), compare [--force] (diff local vs CF)

## Project Structure
- **scripts_new/** (new version):
  - entryPoint.py: Venv creation/install (requests, tenacity), runs cloudflare_sync.py.
  - cloudflare_sync.py: Core—normalize_ip (IPv6 /64), query_active_bans (SQLite), api_add/del/get_all_items (CF API with retry/tenacity, improved pagination using cursors.after and total_count validation, bulk_add/bulk_delete for efficient batch operations, caching in cf_items_cache.json for repeated list fetches), actions (ban/del/start/stop/flush_cf/flush_cache/local_info/compare). Optimized for startup sync (bulk), ban restore (no DB check), stop bulk clear (flushes all from CF), manual ops (DB query, diff). Includes safe_json for handling invalid API responses (prevents crashes on auth errors). Reduced verbose raw API debug logs; errors now log raw response snippets at ERROR level.
  - cloudflare_auth.sh: Exports CF_TOKEN/ACCOUNT_ID/LIST_ID, LOG_LEVEL=INFO, ENABLE_START_SYNC=true, CF_CACHE_TTL=3600 (cache TTL in seconds), etc. (hardcoded; source in actions).

- **action.d/**:
  - cloudflare-list-new.conf: Hooks—actionstart (start sync if enabled)/stop (bulk clear CF)/ban (add IP)/unban (del IP)/flush (skips per-IP unbans on stop) source auth.sh && run entryPoint.py `<args>`. Note: unban removes individual IPs from CF; actionflush = true prevents per-IP invocations on daemon stop; for no individual unbans, set actionunban = `%(action_)s` in jail.conf (noop).

- **jail.d/**:
  - myjails.conf: Jails for mattermost, nginx-breach/http-auth/badbots/botsearch, php-url-fopen, owncloud, sshd, recidive (action=cloudflare-list-new; ignoreips: locals/CF ranges).
  - wordpress.conf: wordpress-hard/soft (logpath=`/var/log/auth.log`; action=cloudflare-list-new).
  - joomla.conf: joomla-login (logpath=`/var/www/...`; action=cloudflare-list-new).

- Old version: scripts/ (similar, uses .env; action=cloudflare-list.conf) for backward compat.

## Development Workflow
- Standards: PEP8, snake_case, type hints. No secrets in code. Log actions. Retry transients.
- Testing: Manual—fail2ban-client ban/unban, check logs/API. IPv6 test /64. No units; add unittest for API mocks.
- Deployment: Copy to `/etc/fail2ban/`, `chmod +x`, restart fail2ban. Use Ansible for multi-server.
- Contribution: Git branches, test API (rate: ~1200/min), PR with changes/tests.

## Key Concepts
- Jail: Log monitor + filter for bans.
- Action: Triggers sync on ban/unban.
- WAF List: CF blocks IPs/subnets at edge.
- Normalize: IPv4 plain, IPv6 ::/64 (broad; configurable).
- Idempotent: Checks existing before add/del.
- Start Sync: Optional resync on Fail2Ban start (ENABLE_START_SYNC=true); uses bulk ops for speed.
- Stop Clear: Bulk flushes all from CF on Fail2Ban stop (actionstop).
- Bulk Operations: bulk_add/bulk_delete handle up to 1000 items per API call to avoid timeouts/delays.
- Caching: api_get_all_items caches `{ip: id}` in cf_items_cache.json (TTL via CF_CACHE_TTL=3600s); invalidated after modifications (add/del/bulk ops) for consistency; reduces repeated fetches. Improved pagination fetches all items with cursor-based looping, total_count tracking (warns on incomplete fetches), and batch debugging. Manual flush_cache clears it.
- Manual Actions: flush_cf (bulk clear CF, invalidates cache), local_info (query DB: total/count/list IPs/query IP), compare (diff local vs CF, always invalidates cache for fresh fetch).
- Error Handling: safe_json parses API responses safely, logs raw text on invalid JSON (e.g., auth failures). Reduced raw API response logging to avoid noise (removed from auth test, safe_json, bulk ops, GET); bulk add/delete errors now log raw response snippets at ERROR level for better diagnostics.

## Troubleshooting
- Script fail: Check venv (python3-venv), `chmod +x`, logs.
- API 401/403: Token scopes/creds in auth.sh.
- Duplicates: Script skips.
- IPv6 broad: Adjust SUBNET_IPV6.
- No trigger: Verify logpath/filter with fail2ban-regex; jail enabled.
- Rate limits: Bulk ops minimize calls; retries handle transients.
- Startup timeout: Bulk sync ensures <60s; disable ENABLE_START_SYNC if needed.
- Restore bans skip: Fixed—no DB check in action_ban.
- Stop delays: Cache invalidated post-mod; next fetch gets fresh data; check cf_items_cache.json (remove if stale).
- Cache issues: Set CF_CACHE_TTL shorter; LOG_LEVEL=DEBUG for details.
- "'str' object has no attribute 'get'": Fixed with safe_json; check logs for raw API errors (likely invalid token).
- Pagination issues: If incomplete fetch (fewer items than total_count), check rate limits, network, or API changes; use DEBUG for batch/params logs.
- Debug: LOG_LEVEL=DEBUG, `tail /var/log/fail2ban-cloudflare-list.log`. Raw API responses logged selectively (errors at ERROR, reduced debug noise).

## References
- Fail2Ban: https://www.fail2ban.org/wiki/
- CF API: https://developers.cloudflare.com/api/ (rules/lists/items)
- Python: requests, ipaddress, tenacity docs.

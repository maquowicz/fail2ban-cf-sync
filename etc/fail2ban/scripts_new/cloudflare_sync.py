#!/usr/bin/env python3
# /etc/fail2ban/scripts/cloudflare_sync.py
# Endpoint: /accounts/{account_id}/rules/lists/{list_id}/items (supports pagination up to 500).
# POST: json=[{"ip": ip_cidr, "comment": "..."} ] (list of dicts).
# DELETE: body={"items": [{"id": item_id}]} (DELETE with body, not path id).

import os
import sys
import logging
import sqlite3
import ipaddress
import time
import json
import requests
from datetime import datetime
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

# Ensure log directory exists
log_dir = '/var/log'
log_file = os.path.join(log_dir, 'fail2ban-cloudflare-list.log')
os.makedirs(log_dir, exist_ok=True)  # Usually exists, but safe

# Configure logging
log_level_str = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, log_level_str),
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)  # Also to stdout for Fail2Ban logs
    ]
)
logger = logging.getLogger(__name__)

# Environment variables (required for auth/config)
CF_EMAIL = os.getenv('CF_EMAIL')
CF_API_KEY = os.getenv('CF_API_KEY')
CF_TOKEN = os.getenv('CF_TOKEN')
CF_ACCOUNT_ID = os.getenv('CF_ACCOUNT_ID')
CF_LIST_ID = os.getenv('CF_LIST_ID')

# Support both legacy (email/key) and modern (token)
use_token = bool(CF_TOKEN) and not (CF_EMAIL and CF_API_KEY)
use_legacy = bool(CF_EMAIL and CF_API_KEY) and not CF_TOKEN
if not (use_token or use_legacy) or not CF_ACCOUNT_ID or not CF_LIST_ID:
    logger.error("Missing required env vars. For token: CF_TOKEN, CF_ACCOUNT_ID, CF_LIST_ID. For legacy: CF_EMAIL, CF_API_KEY, CF_ACCOUNT_ID, CF_LIST_ID")
    sys.exit(1)

# Set headers
headers = {'Content-Type': 'application/json'}
if use_token:
    headers['Authorization'] = f'Bearer {CF_TOKEN}'
    logger.info(f"Using API Token mode (token length: {len(CF_TOKEN)} chars)")
else:
    headers['X-Auth-Email'] = CF_EMAIL
    headers['X-Auth-Key'] = CF_API_KEY
    logger.info(f"Using legacy API Key mode (email: {CF_EMAIL[:10]}...)")

RETRY_COUNT = int(os.getenv('RETRY_COUNT', '3'))
DELAY_SEC = float(os.getenv('DELAY_SEC', '2'))
ENABLE_COMMENTS = os.getenv('ENABLE_COMMENTS', 'true').lower() == 'true'
ENABLE_START_SYNC = os.getenv('ENABLE_START_SYNC', 'false').lower() == 'true'
ENABLE_AUTH_TEST = os.getenv('ENABLE_AUTH_TEST', 'false').lower() == 'true'  # Optional auth test, disabled by default to save API calls
SUBNET_IPV6 = int(os.getenv('SUBNET_IPV6', '64'))
CF_CACHE_TTL = int(os.getenv('CF_CACHE_TTL', '3600'))  # seconds, default 1 hour

DB_PATH = '/var/lib/fail2ban/fail2ban.sqlite3'
BASE_URL = 'https://api.cloudflare.com/client/v4'

# Optional auth test
try:
    if ENABLE_AUTH_TEST:
        test_url = f"{BASE_URL}/accounts/{CF_ACCOUNT_ID}"
        resp = requests.get(test_url, headers=headers)
        logger.debug(f"Raw API response for GET {test_url}: status={resp.status_code}, body={resp.text}")
        if resp.status_code != 200:
            logger.error(f"Auth failed: {resp.status_code} - {resp.text[:200]}. Check credentials and scopes (Account.Rules:Edit + Read for WAF lists).")
            sys.exit(1)
        logger.debug("Auth test passed")
    else:
        logger.info("Skipping auth test")
except requests.exceptions.RequestException as e:
    logger.error(f"Network error during auth test: {e}")
    sys.exit(1)

logger.debug("Requests session initialized successfully (using WAF Rules Lists API)")

def safe_json(resp):
    """Safely parse JSON response, ensure dict; return error dict if not."""
    logger.debug(f"Raw API response in safe_json (status: {resp.status_code}): body={resp.text}")
    try:
        parsed = resp.json()
        if isinstance(parsed, dict):
            return parsed
        else:
            logger.error(f"Unexpected non-dict JSON response (status: {resp.status_code}): type={type(parsed)}, content={str(parsed)[:500]}")
            return {'success': False, 'errors': [{'code': 'unexpected_response', 'message': str(parsed)}]}
    except Exception as e:
        logger.error(f"Invalid JSON response (status: {resp.status_code}): {e}. Raw: {resp.text[:500]}")
        return {'success': False, 'errors': [{'code': 'invalid_json', 'message': str(e)}]}

# Update normalize_ip:
def normalize_ip(ip_str: str) -> str:
    """Normalize IP: str(ip) for IPv4, /64 for IPv6."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 6:
            # Mimic old script: truncate to /64
            first_64_bits = ':'.join(str(ip).split(':')[:4]) + '::/64'
            return first_64_bits
        else:
            return str(ip)  # No /32 for IPv4; CF stores plain IP
    except ValueError:
        logger.error(f"Invalid IP: {ip_str}")
        sys.exit(1)

@retry(stop=stop_after_attempt(RETRY_COUNT), wait=wait_exponential(multiplier=1, min=1, max=10), retry=retry_if_exception_type((requests.exceptions.RequestException,)))
def api_add(ip_cidr: str, comment: str = None):
    """Add single IP to WAF Rules list with retry (POST array)."""
    return bulk_add([(ip_cidr, comment)])

@retry(stop=stop_after_attempt(RETRY_COUNT), wait=wait_exponential(multiplier=1, min=1, max=10), retry=retry_if_exception_type((requests.exceptions.RequestException, requests.exceptions.HTTPError)))
def bulk_add(to_add: list):
    """Bulk add IPs to WAF Rules list (POST array of dicts)."""
    if not to_add:
        return
    payload = []
    for ip_cidr, comment in to_add:
        entry = {"ip": ip_cidr}
        if comment:
            entry["comment"] = comment
        payload.append(entry)
    url = f"{BASE_URL}/accounts/{CF_ACCOUNT_ID}/rules/lists/{CF_LIST_ID}/items"
    resp = requests.post(url, headers=headers, json=payload)
    logger.debug(f"Raw API response for POST {url}: status={resp.status_code}, body={resp.text}")
    if resp.status_code == 429:
        retry_after = int(resp.headers.get('retry-after', 60))
        logger.warning(f"Rate limited (429). Backing off for {retry_after}s")
        time.sleep(retry_after)
        raise requests.exceptions.HTTPError(f"Rate limited: {resp.text}")
    data = safe_json(resp)
    if resp.status_code in [200, 201]:
        if data.get('success', False):
            logger.info(f"Requested bulk add for {len(to_add)} IPs to WAF Rules list")
            return
        else:
            logger.warning(f"API success false despite 200/201: {data}")
    errors = data.get('errors', [])
    if isinstance(errors, list):
        for error in errors:
            if isinstance(error, dict):
                code = error.get('code')
                target = error.get('target', {})
                ip_idx = target.get('ip', {}).get('index', 0) if isinstance(target, dict) else 0
                if ip_idx < len(to_add):
                    ip_cidr = to_add[ip_idx][0]
                    if code == 'ip_already_exist' or resp.status_code == 409:
                        logger.info(f"IP {ip_cidr} already exists; skipping")
                    else:
                        logger.warning(f"Bulk add partial fail for {ip_cidr} (code: {code})")
            else:
                logger.warning(f"Skipping non-dict error: {error}")
    else:
        logger.warning(f"Unexpected errors type: {type(errors)} - {errors}")
    if not data.get('success', False):
        logger.debug(f"Raw API response on bulk add failure: status={resp.status_code}, body={resp.text}")
        raise requests.exceptions.RequestException(f"Bulk add failed: {data}")

@retry(stop=stop_after_attempt(RETRY_COUNT), wait=wait_exponential(multiplier=1, min=1, max=10), retry=retry_if_exception_type((requests.exceptions.RequestException,)))
def api_delete(item_id: str):
    """Delete single item from WAF Rules list (DELETE with body items array)."""
    return bulk_delete([item_id])

@retry(stop=stop_after_attempt(RETRY_COUNT), wait=wait_exponential(multiplier=1, min=1, max=10), retry=retry_if_exception_type((requests.exceptions.RequestException, requests.exceptions.HTTPError)))
def bulk_delete(item_ids: list):
    """Bulk delete items from WAF Rules list (DELETE with body items array)."""
    if not item_ids:
        return
    payload = {"items": [{"id": item_id} for item_id in item_ids]}
    url = f"{BASE_URL}/accounts/{CF_ACCOUNT_ID}/rules/lists/{CF_LIST_ID}/items"
    resp = requests.delete(url, headers=headers, json=payload)
    logger.debug(f"Raw API response for DELETE {url}: status={resp.status_code}, body={resp.text}")
    if resp.status_code == 429:
        retry_after = int(resp.headers.get('retry-after', 60))
        logger.warning(f"Rate limited (429). Backing off for {retry_after}s")
        time.sleep(retry_after)
        raise requests.exceptions.HTTPError(f"Rate limited: {resp.text}")
    data = safe_json(resp)
    if resp.status_code in [200, 204]:
        if data.get('success', False):
            for item_id in item_ids:
                logger.info(f"Deleted item {item_id} from WAF Rules list")
            return item_ids
    errors = data.get('errors', [])
    if isinstance(errors, list):
        for error in errors:
            if isinstance(error, dict):
                code = error.get('code')
                target = error.get('target', {})
                id_idx = target.get('id', {}).get('index', 0) if isinstance(target, dict) else 0
                if id_idx < len(item_ids):
                    item_id = item_ids[id_idx]
                    if code in ['unknown_item', 'not_found'] or resp.status_code == 404:
                        logger.info(f"Item {item_id} not found; skipping")
                    else:
                        logger.warning(f"Bulk delete partial fail for {item_id} (code: {code})")
            else:
                logger.warning(f"Skipping non-dict error: {error}")
    else:
        logger.warning(f"Unexpected errors type: {type(errors)} - {errors}")
    if not data.get('success', False):
        logger.debug(f"Raw API response on bulk delete failure: status={resp.status_code}, body={resp.text}")
        raise requests.exceptions.RequestException(f"Bulk delete failed: {data}")


def api_get_all_items() -> dict:
    """Get all items from WAF Rules list (cursor pagination). Returns {ip_cidr: item_id} dict."""
    # Cache logic
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cache_file = os.path.join(script_dir, 'cf_items_cache.json')
    items = {}
    if os.path.exists(cache_file):
        try:
            stat = os.stat(cache_file)
            if time.time() - stat.st_mtime < CF_CACHE_TTL:
                with open(cache_file, 'r') as f:
                    items = json.load(f)
                logger.debug(f"Loaded CF items from cache: {len(items)} items")
                return items
            else:
                os.remove(cache_file)
                logger.debug("Cache expired; fetching fresh")
        except (OSError, json.JSONDecodeError, KeyError) as e:
            logger.debug(f"Cache invalid ({e}); fetching fresh")
    
    # Fetch fresh
    url = f"{BASE_URL}/accounts/{CF_ACCOUNT_ID}/rules/lists/{CF_LIST_ID}/items"
    per_page = 500
    cursor = None
    while True:
        params = {'per_page': per_page}
        if cursor:
            params['cursor'] = cursor
        resp = requests.get(url, headers=headers, params=params)
        logger.debug(f"Raw API response for GET {url} (cursor: {cursor or 'initial'}): status={resp.status_code}, body={resp.text}")
        if resp.status_code == 429:
            retry_after = int(resp.headers.get('retry-after', 60))
            logger.warning(f"Rate limited (429) on GET. Backing off for {retry_after}s")
            time.sleep(retry_after)
            raise requests.exceptions.HTTPError(f"Rate limited: {resp.text}")
        data = safe_json(resp)
        if resp.status_code != 200:
            error_code = (data.get('errors', [{}])[0].get('code') if 'errors' in data else None)
            if error_code == 'not_found' or resp.status_code == 404:
                break
            logger.error(f"Get items error (cursor: {cursor or 'initial'}) (status: {resp.status_code}): {error_code} - {data.get('errors', [])}. Response: {resp.text[:200]}")
            raise requests.exceptions.RequestException(f"Failed to get items: {data}")
        if not data.get('success', False):
            logger.warning(f"API not success: {data}")
            break
        result_list = data.get('result', [])
        if isinstance(result_list, list):
            for item in result_list:
                if isinstance(item, dict):
                    ip_cidr = item.get('ip')
                    item_id = item.get('id')
                    if ip_cidr:
                        items[ip_cidr] = item_id
                else:
                    logger.warning(f"Skipping non-dict item in result: {item}")
        else:
            logger.warning(f"Unexpected result type: {type(result_list)} - {result_list}")
        if not result_list:
            break
        logger.debug(f"Fetched batch (cursor: {cursor or 'initial'}): {len(result_list)} items")
        
        # Get next cursor
        result_info = data.get('result_info', {}) or data.get('meta', {})
        cursor = result_info.get('cursor')
        if not cursor:
            break
    
    # Cache the result
    try:
        with open(cache_file, 'w') as f:
            json.dump(items, f)
        logger.debug(f"Cached CF items: {len(items)} items")
    except OSError as e:
        logger.warning(f"Failed to cache CF items: {e}")
    
    logger.info(f"Total items in WAF Rules list: {len(items)}")
    return items

def save_cache(items: dict):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cache_file = os.path.join(script_dir, 'cf_items_cache.json')
    try:
        with open(cache_file, 'w') as f:
            json.dump(items, f)
        os.utime(cache_file, None)
        logger.debug(f"Updated cache with {len(items)} items")
    except Exception as e:
        logger.warning(f"Failed to update cache: {e}")

def invalidate_cache():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cache_file = os.path.join(script_dir, 'cf_items_cache.json')
    if os.path.exists(cache_file):
        try:
            os.remove(cache_file)
            logger.debug("Invalidated CF cache")
        except OSError as e:
            logger.warning(f"Failed to invalidate cache: {e}")
    else:
        logger.debug("No cache to invalidate")

def query_active_bans(jail: str = None) -> dict:
    """Query active bans from DB. Returns {ip: {'jail': str, 'bantime': int, 'timeofban': float}}."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        now = datetime.utcnow().timestamp()
        if jail:
            query = "SELECT ip, jail, bantime, timeofban FROM bips WHERE jail = ? AND (bantime <= -1 OR (timeofban + bantime) > ?)"
            rows = conn.execute(query, (jail, now)).fetchall()
        else:
            query = "SELECT ip, jail, bantime, timeofban FROM bips WHERE (bantime <= -1 OR (timeofban + bantime) > ?)"
            rows = conn.execute(query, (now,)).fetchall()
        bans = {row['ip']: dict(row) for row in rows}
        logger.debug(f"Active bans for '{jail or 'all'}': {len(bans)}")
        return bans
    except sqlite3.Error as e:
        logger.error(f"DB error: {e}")
        return {}
    finally:
        if 'conn' in locals():
            conn.close()

def action_ban(ip: str, jail: str):
    ip_cidr = normalize_ip(ip)
    comment = f"Banned by {jail}" if ENABLE_COMMENTS else None  # Simple comment

    cf_items = api_get_all_items()
    if ip_cidr in cf_items:
        logger.info(f"IP {ip_cidr} already in list; skipping")
        return

    try:
        api_add(ip_cidr, comment)
        logger.info(f"Added {ip_cidr} to WAF Rules list")
        invalidate_cache()
    except Exception as e:
        logger.error(f"Failed to add {ip}: {e}")

def action_unban(ip: str):
    ip_cidr = normalize_ip(ip)
    cf_items = api_get_all_items()
    if ip_cidr not in cf_items:
        logger.info(f"IP {ip_cidr} not in list; skipping")
        return
    item_id = cf_items[ip_cidr]
    try:
        api_delete(item_id)
        invalidate_cache()
        logger.info(f"Removed {ip_cidr} from WAF Rules list")
    except Exception as e:
        logger.error(f"Failed to delete {ip_cidr}: {e}")
        # On error, refetch to sync
        cf_items = api_get_all_items()
        save_cache(cf_items)

def action_start():
    if not ENABLE_START_SYNC:
        logger.info("Sync disabled")
        return

    lock_file = '/tmp/fail2ban_cf_sync.lock'
    lock_active = False
    if os.path.exists(lock_file):
        mtime = os.path.getmtime(lock_file)
        if time.time() - mtime < 30:  # 30s lock window
            logger.info("Sync skipped: lock active (another instance running)")
            return
        else:
            os.remove(lock_file)  # Stale lock

    # Create lock
    try:
        with open(lock_file, 'w') as f:
            f.write(str(os.getpid()))
        lock_active = True
        logger.info("Starting sync...")
        active_bans = query_active_bans()
        active_cidr_set = {normalize_ip(ip) for ip in active_bans}
        cf_items = api_get_all_items()
        # Collect adds and deletes
        to_add = []
        for ip in active_bans:
            ip_cidr = normalize_ip(ip)
            if ip_cidr not in cf_items:
                ban_info = active_bans[ip]
                comment = f"Banned by {ban_info['jail']}" if ENABLE_COMMENTS else None
                to_add.append((ip_cidr, comment))
        to_delete_ips = [ip_cidr for ip_cidr in cf_items if ip_cidr not in active_cidr_set]
        to_delete_ids = [cf_items[ip_cidr] for ip_cidr in to_delete_ips]
        # Bulk operations
        try:
            if to_add:
                bulk_add(to_add)
            if to_delete_ids:
                bulk_delete(to_delete_ids)
            invalidate_cache()
        except Exception as e:
            logger.error(f"Bulk sync failed: {e}")
            invalidate_cache()
        logger.info("Sync complete")
    finally:
        if lock_active and os.path.exists(lock_file):
            os.remove(lock_file)

def action_flush_cf():
    """Manual: Bulk clear all items from CF list."""
    logger.info("Manual flush: Clearing all items from CF list")
    cf_items = api_get_all_items()
    if not cf_items:
        logger.info("CF list already empty")
        return
    item_ids = list(cf_items.values())
    try:
        bulk_delete(item_ids)
        invalidate_cache()
        logger.info(f"Flushed {len(item_ids)} items from CF list")
    except Exception as e:
        logger.error(f"Failed to flush CF list: {e}")
        cf_items = api_get_all_items()
        save_cache(cf_items)

def action_flush_cache():
    """Manual: Clear local CF cache file."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cache_file = os.path.join(script_dir, 'cf_items_cache.json')
    if os.path.exists(cache_file):
        try:
            os.remove(cache_file)
            logger.info("Cleared CF cache file")
        except OSError as e:
            logger.error(f"Failed to clear cache: {e}")
    else:
        logger.info("No cache file to clear")

def action_local_info(subaction: str = None, query_ip: str = None):
    """Manual: Get info on local Fail2Ban bans from DB."""
    active_bans = query_active_bans()
    if not active_bans:
        logger.info("No active bans in DB")
        return
    if subaction == 'total' or subaction == 'count':
        logger.info(f"Total active bans: {len(active_bans)}")
    elif subaction == 'list':
        logger.info("Active banned IPs:")
        for ip in sorted(active_bans.keys()):
            ban = active_bans[ip]
            logger.info(f"  {ip} (jail: {ban['jail']}, time: {datetime.fromtimestamp(ban['timeofban'])})")
    elif subaction == 'query' and query_ip:
        norm_ip = normalize_ip(query_ip)
        if query_ip in active_bans:
            ban = active_bans[query_ip]
            logger.info(f"IP {query_ip} is active banned (jail: {ban['jail']}, time: {datetime.fromtimestamp(ban['timeofban'])})")
        else:
            logger.info(f"IP {query_ip} not actively banned")
    else:
        logger.error("Invalid subaction for local_info: total, count, list, or query <ip>")

def action_stop():
    """Bulk clear all items from CF list on Fail2Ban stop."""
    logger.info("Stop event: Clearing all items from CF list")
    cf_items = api_get_all_items()
    if not cf_items:
        logger.info("CF list already empty")
        return
    item_ids = list(cf_items.values())
    try:
        bulk_delete(item_ids)
        invalidate_cache()
        logger.info(f"Cleared {len(item_ids)} items from CF list")
    except Exception as e:
        logger.error(f"Failed to clear CF list: {e}")
        # Refetch on error
        cf_items = api_get_all_items()
        save_cache(cf_items)

def action_compare(force: bool = False):
    """Manual: Compare local bans vs CF list (print diffs)."""
    logger.info("Comparing local bans vs CF list")
    active_bans = query_active_bans()
    local_cidr_set = {normalize_ip(ip) for ip in active_bans}
    logger.info("Fetching fresh CF items for compare (cache invalidated)")
    invalidate_cache()
    cf_items = api_get_all_items()
    cf_cidr_set = set(cf_items.keys())
    to_add = local_cidr_set - cf_cidr_set
    to_delete = cf_cidr_set - local_cidr_set
    logger.info(f"Local active bans: {len(local_cidr_set)}")
    logger.info(f"CF list items: {len(cf_cidr_set)}")
    if to_add:
        logger.info("IPs in local but not CF (to add):")
        for ip_cidr in sorted(to_add):
            logger.info(f"  {ip_cidr}")
    else:
        logger.info("No IPs to add")
    if to_delete:
        logger.info("IPs in CF but not local (to delete):")
        for ip_cidr in sorted(to_delete):
            logger.info(f"  {ip_cidr}")
    else:
        logger.info("No IPs to delete")
    if not to_add and not to_delete:
        logger.info("Local and CF are in sync")

# Main
if __name__ == '__main__':
    if len(sys.argv) < 2:
        logger.error("Usage: <action> [args...]")
        sys.exit(1)
    action = sys.argv[1]
    try:
        if action == 'ban' and len(sys.argv) >= 3:
            jail = sys.argv[3] if len(sys.argv) > 3 else ''
            action_ban(sys.argv[2], jail)
        elif action == 'del' and len(sys.argv) == 3:
            action_unban(sys.argv[2])
        elif action == 'start' and len(sys.argv) == 2:
            action_start()
        elif action == 'stop' and len(sys.argv) == 2:
            action_stop()
        elif action == 'flush_cf' and len(sys.argv) == 2:
            action_flush_cf()
        elif action == 'flush_cache' and len(sys.argv) == 2:
            action_flush_cache()
        elif action == 'local_info':
            if len(sys.argv) == 2:
                action_local_info('total')
            elif len(sys.argv) == 3 and sys.argv[2] in ['total', 'count', 'list']:
                action_local_info(sys.argv[2])
            elif len(sys.argv) == 4 and sys.argv[2] == 'query':
                action_local_info('query', sys.argv[3])
            else:
                logger.error("local_info usage: local_info [total|count|list|query <ip>]")
                sys.exit(1)
        elif action == 'compare' and len(sys.argv) in [2, 3]:
            force = len(sys.argv) == 3 and sys.argv[2] == '--force'
            if len(sys.argv) == 3 and not force:
                logger.error("compare usage: compare [--force]")
                sys.exit(1)
            action_compare(force)
        else:
            logger.error(f"Invalid args: {sys.argv}")
            sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Interrupted")
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

#!/bin/sh
# /etc/fail2ban/cloudflare_auth.sh - Secure env exports for Cloudflare API.

# For Token (recommended):
export CF_TOKEN="change_me"  # From Cloudflare API > Tokens (scopes: Account.Rules:Edit + Read)
export CF_ACCOUNT_ID="change_me"
export CF_LIST_ID="change_me"

# OR for Legacy (if preferred):
# export CF_EMAIL=""
# export CF_API_KEY=""
# export CF_ACCOUNT_ID=""
# export CF_LIST_ID=""

# Configs (optional overrides):
export LOG_LEVEL="INFO"  # INFO or DEBUG
export ENABLE_START_SYNC="true"  # Optional resync on Fail2Ban restart
export ENABLE_COMMENTS="true"
export DELAY_SEC="2"
export RETRY_COUNT="3"
export SUBNET_IPV6="64"  # /64 for broad IPv6 blocking
export CF_CACHE_TTL="300"
export ENABLE_AUTH_TEST="false"

# Security: Restrict access
#chmod 700 /etc/fail2ban/cloudflare_auth.sh
#chown root:root /etc/fail2ban/cloudflare_auth.sh

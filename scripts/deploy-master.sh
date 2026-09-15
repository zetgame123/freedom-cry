#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# FREEDOM CRY 2.0 — MASTER SERVER PRODUCTION DEPLOYMENT ENGINE
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "=================================================="
echo "    🦅 Freedom Cry Master Production Deployer     "
echo "=================================================="

# 1. Dependency checks
command -v docker >/dev/null 2>&1 || { echo "[!] Docker is required but not installed. Aborting."; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "[!] Docker Compose v2 is required. Aborting."; exit 1; }

# 2. Environment generation
ENV_FILE="${ROOT_DIR}/.env"
if [ ! -f "${ENV_FILE}" ]; then
    echo "[*] Generating high-entropy production secrets in .env..."
    
    DB_PASS=$(openssl rand -hex 24)
    REDIS_PASS=$(openssl rand -hex 24)
    JWT_SEC=$(openssl rand -hex 32)
    MFA_SEC=$(openssl rand -hex 16)
    PROBE_SEC=$(openssl rand -hex 24)

    cat <<EOF > "${ENV_FILE}"
# ------------------------------------------------------------------------------
# FREEDOM CRY PRODUCTION CONFIGURATION
# ------------------------------------------------------------------------------
DOMAIN=vpn.example.com
BASE_URL=https://vpn.example.com

# Database
DB_USER=freedomcry
DB_NAME=freedomcry_db
DB_PASSWORD=${DB_PASS}

# Redis
REDIS_PASSWORD=${REDIS_PASS}

# Cryptography & Auth
JWT_SECRET=${JWT_SEC}
PROBE_SECRET=${PROBE_SEC}
ADMIN_INITIAL_PASSWORD=$(openssl rand -base64 16)

# Telegram Bots (Fill in your actual tokens from @BotFather)
CLIENT_BOT_TOKEN=
ADMIN_BOT_TOKEN=
ADMIN_TELEGRAM_IDS=
ADMIN_MFA_SECRET=${MFA_SEC}
EOF
    echo "[+] Created ${ENV_FILE} with auto-generated secure credentials."
    echo "[!] Please edit ${ENV_FILE} to specify your DOMAIN and TELEGRAM bot tokens."
else
    echo "[+] Using existing ${ENV_FILE}"
fi

# 3. Build and launch cluster
echo "[*] Building and starting production cluster..."
docker compose -f docker-compose.prod.yml up -d --build

# 4. Wait for healthcheck
echo "[*] Waiting for services to become healthy..."
sleep 5

docker compose -f docker-compose.prod.yml ps

echo "=================================================="
echo "    ✅ Freedom Cry Production Cluster Deployed!    "
echo "=================================================="
echo "Master API: https://\$(grep DOMAIN .env | cut -d= -f2)/health"
echo "Subscription Link Format: https://\$(grep DOMAIN .env | cut -d= -f2)/sub/<token>"
echo "Sing-box Profile Format: https://\$(grep DOMAIN .env | cut -d= -f2)/sub/<token>/singbox"
echo "Logs: docker compose -f docker-compose.prod.yml logs -f"
echo "=================================================="

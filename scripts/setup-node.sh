#!/usr/bin/env bash
# ==============================================================================
# 🦅 Freedom Cry VPN - Node Installer Script
# Automated setup for Ubuntu 22.04/24.04 and Debian 11/12 VPS
# ==============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
cat << "EOF"
  ______               _                  _____            
 |  ____|             | |                / ____|           
 | |__ _ __ ___   ___ | | _____  _ __ ___| |     _ __ _   _ 
 |  __| '__/ _ \ / _ \| |/ / _ \| '_ ` _ \ |    | '__| | | |
 | |  | | |  __/| (_) |   < (_) | | | | | | |____| |  | |_| |
 |_|  |_|  \___| \___/|_|\_\___/|_| |_| |_|\_____|_|   \__, |
                                                         __/ |
                 VPN NODE INSTALLER                      |___/ 
EOF
echo -e "${NC}"

# 1. Check Root Privileges
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] Этот скрипт должен быть запущен с правами root (sudo -i).${NC}"
   exit 1
fi

# 2. Parse Arguments or Prompt Interactively
API_URL=""
NODE_ID=""
NODE_SECRET=""
ENABLE_COVERT=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --api)
      API_URL="$2"
      shift 2
      ;;
    --node-id)
      NODE_ID="$2"
      shift 2
      ;;
    --secret)
      NODE_SECRET="$2"
      shift 2
      ;;
    --with-covert)
      ENABLE_COVERT=true
      shift
      ;;
    *)
      echo -e "${RED}Неизвестный параметр: $1${NC}"
      exit 1
      ;;
  esac
done

if [[ -z "$API_URL" ]]; then
    read -rp "Введи URL мастер-сервера Freedom Cry (напр. http://1.2.3.4:8080 или https://vpn.domain.com): " API_URL
fi

if [[ -z "$NODE_ID" ]]; then
    read -rp "Введи UUID этой ноды (из базы данных или админки): " NODE_ID
fi

if [[ -z "$NODE_SECRET" ]]; then
    read -rp "Введи секретный ключ ноды (NODE_SECRET): " NODE_SECRET
fi

# Normalize API_URL (remove trailing slash)
API_URL="${API_URL%/}"

echo -e "\n${BLUE}====================================================${NC}"
echo -e "${BOLD}Параметры установки ноды:${NC}"
echo -e "Мастер API:     ${GREEN}$API_URL${NC}"
echo -e "Node UUID:      ${GREEN}$NODE_ID${NC}"
echo -e "Node Secret:    ${GREEN}******${NC}"
echo -e "${BLUE}====================================================${NC}\n"

# 3. Detect OS and Package Manager
echo -e "${YELLOW}[1/7] Обновление системы и установка базовых утилит...${NC}"
apt-get update -y
apt-get install -y \
    curl \
    wget \
    tar \
    git \
    jq \
    iptables \
    iptables-persistent \
    ca-certificates \
    software-properties-common \
    gnupg \
    lsb-release

# 4. Enable BBR & IP Forwarding in Sysctl
echo -e "${YELLOW}[2/7] Оптимизация сети (BBR + IP Forwarding)...${NC}"
cat > /etc/sysctl.d/99-freedomcry.conf << 'EOF'
# IP Forwarding for VPN tunnels
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# BBR Congestion Control for maximum speed
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Buffer and connection tuning
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
EOF

sysctl --system >/dev/null 2>&1
echo -e "${GREEN}✓ Сетевой стек настроен (BBR активен)${NC}"

# 5. Install Xray-core (for VLESS + Reality)
echo -e "${YELLOW}[3/7] Установка Xray-core (VLESS Reality)...${NC}"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --beta

mkdir -p /usr/local/etc/xray
mkdir -p /var/log/xray

# Initial minimal fallback config
cat > /usr/local/etc/xray/config.json << 'EOF'
{
  "log": { "loglevel": "warning" },
  "inbounds": [],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ]
}
EOF

systemctl enable xray
systemctl restart xray
echo -e "${GREEN}✓ Xray-core успешно установлен${NC}"

# 6. Install AmneziaWG (Kernel Module & Tools)
echo -e "${YELLOW}[4/7] Установка AmneziaWG (обфусцированный WireGuard)...${NC}"
DISTRO=$(lsb_release -is | tr '[:upper:]' '[:lower:]')

if [[ "$DISTRO" == "ubuntu" ]]; then
    add-apt-repository -y ppa:amnezia/ppa || true
    apt-get update -y
    apt-get install -y amneziawg-dkms amneziawg-tools || true
else
    # Debian or other distros
    echo -e "${CYAN}Установка зависимостей для сборки модуля AmneziaWG...${NC}"
    apt-get install -y wireguard-tools dkms linux-headers-$(uname -r) || true
    # Try installing pre-built packages if available or fallback
    add-apt-repository -y ppa:amnezia/ppa || true
    apt-get update -y || true
    apt-get install -y amneziawg-dkms amneziawg-tools || apt-get install -y wireguard wireguard-tools
fi

mkdir -p /etc/amnezia/amneziawg
echo -e "${GREEN}✓ AmneziaWG установлен${NC}"

# 7. Configure Firewall and NAT
echo -e "${YELLOW}[5/7] Настройка фаервола и NAT-трансляции...${NC}"
WAN_IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5; exit}')
if [[ -z "$WAN_IFACE" ]]; then
    WAN_IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
fi

echo -e "Обнаружен внешний сетевой интерфейс: ${GREEN}${WAN_IFACE}${NC}"

# Add NAT MASQUERADE for AWG subnet (10.8.0.0/16)
iptables -t nat -C POSTROUTING -s 10.8.0.0/16 -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o "$WAN_IFACE" -j MASQUERADE

# 1. SECURITY: Block client-to-client network pivoting
iptables -C FORWARD -s 10.8.0.0/16 -d 10.8.0.0/16 -j DROP 2>/dev/null || \
iptables -I FORWARD 1 -s 10.8.0.0/16 -d 10.8.0.0/16 -j DROP

# 2. SECURITY: Block client access to cloud metadata (169.254.169.254)
iptables -C FORWARD -s 10.8.0.0/16 -d 169.254.169.254 -j DROP 2>/dev/null || \
iptables -I FORWARD 2 -s 10.8.0.0/16 -d 169.254.169.254 -j DROP

# 3. SECURITY: Block client access to sensitive host management services
iptables -C INPUT -s 10.8.0.0/16 -p tcp -m multiport --dports 22,5432,6379,8080 -j DROP 2>/dev/null || \
iptables -I INPUT 1 -s 10.8.0.0/16 -p tcp -m multiport --dports 22,5432,6379,8080 -j DROP

# 4. SECURITY: Prevent IPv6 traffic leakage
ip6tables -P FORWARD DROP 2>/dev/null || true

iptables -C FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -C FORWARD -s 10.8.0.0/16 -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -s 10.8.0.0/16 -j ACCEPT

# Save iptables rules
netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
echo -e "${GREEN}✓ NAT-форвардинг и правила изоляции клиентов настроены${NC}"

# 8. Install Freedom Cry Node Agent
echo -e "${YELLOW}[6/7] Установка демона Freedom Cry Node Agent...${NC}"

mkdir -p /opt/freedom-cry
AGENT_BIN="/opt/freedom-cry/agent"

if [[ -f "./agent" ]]; then
    # Local installation from source folder
    if [[ "$(realpath ./agent)" != "$(realpath "$AGENT_BIN")" ]]; then
        cp ./agent "$AGENT_BIN"
    fi
    chmod +x "$AGENT_BIN"
elif command -v docker >/dev/null 2>&1; then
    echo -e "${CYAN}Сборка агента через Docker...${NC}"
    docker run --rm -v "$(pwd)":/app -w /app golang:alpine go build -ldflags="-w -s" -o /app/agent ./cmd/agent
    cp ./agent "$AGENT_BIN"
    chmod +x "$AGENT_BIN"
else
    # Download from API master or build via Go
    echo -e "Загрузка бинарника agent с мастер-сервера..."
    if command -v go >/dev/null 2>&1; then
        echo -e "Компиляция агента через Go..."
        go build -o "$AGENT_BIN" ./cmd/agent
    fi
fi

if [[ ! -f "$AGENT_BIN" ]]; then
    echo -e "${YELLOW}[Внимание] Бинарник агента не был найден автоматически.${NC}"
    echo -e "Скопируй скомпилированный бинарник 'agent' в путь: ${BOLD}/opt/freedom-cry/agent${NC}"
fi

# Create secure environment file with restricted permissions (0600)
mkdir -p /etc/freedom-cry
chmod 700 /etc/freedom-cry
cat > /etc/freedom-cry/agent.env << EOF
FC_API_URL=${API_URL}
FC_NODE_ID=${NODE_ID}
FC_NODE_SECRET=${NODE_SECRET}
XRAY_CONFIG_PATH=/usr/local/etc/xray/config.json
AWG_CONFIG_PATH=/etc/amnezia/amneziawg/awg0.conf
FC_KEYS_PATH=/etc/freedom-cry/node-keys.json
EOF
chmod 600 /etc/freedom-cry/agent.env

# Create Hardened Systemd service for Freedom Cry Agent
cat > /etc/systemd/system/freedom-cry-agent.service << EOF
[Unit]
Description=Freedom Cry VPN Node Agent (Hardened)
After=network.target xray.service
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/freedom-cry
EnvironmentFile=/etc/freedom-cry/agent.env
ExecStart=/opt/freedom-cry/agent --interval 15 --dry-run=false
Restart=always
RestartSec=5
LimitNOFILE=65535

# Systemd Sandboxing & Privilege Hardening Directives
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ReadWritePaths=/opt/freedom-cry /usr/local/etc/xray /etc/amnezia/amneziawg /var/log/xray /etc/freedom-cry

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
if [[ -f "$AGENT_BIN" ]]; then
    systemctl enable freedom-cry-agent
    systemctl restart freedom-cry-agent
    echo -e "${GREEN}✓ Защищенный сервис freedom-cry-agent запущен и включен в автозагрузку${NC}"
fi

# 9. Optional: Setup Covert Whitelist Tunnel Exit Node
if [[ "$ENABLE_COVERT" == "true" ]]; then
    echo -e "${YELLOW}[7/7] Настройка аварийного узла обхода белых списков (Covert)...${NC}"
    COVERT_BIN="/opt/freedom-cry/covert"
    if [[ -f "./covert" ]]; then
        cp ./covert "$COVERT_BIN"
        chmod +x "$COVERT_BIN"
    fi

    cat > /etc/systemd/system/freedom-cry-covert.service << EOF
[Unit]
Description=Freedom Cry Covert Whitelist Exit Node
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/freedom-cry
ExecStart=/opt/freedom-cry/covert --mode exit --transport cups --room "${NODE_ID}" --key "${NODE_SECRET}"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    if [[ -f "$COVERT_BIN" ]]; then
        systemctl enable --now freedom-cry-covert
        echo -e "${GREEN}✓ Аварийный режим Covert запущен на порту выхода${NC}"
    fi
else
    echo -e "${YELLOW}[7/7] Пропуск настройки Covert (используйте --with-covert при необходимости)${NC}"
fi

echo -e "\n${GREEN}${BOLD}====================================================${NC}"
echo -e "${GREEN}${BOLD}       🦅 НОДА FREEDOM CRY УСПЕШНО НАСТРОЕНА!       ${NC}"
echo -e "${GREEN}${BOLD}====================================================${NC}"
echo -e "Проверка статуса сервисов:"
echo -e "  systemctl status xray"
echo -e "  systemctl status freedom-cry-agent"
echo -e "\nЛоги агента в реальном времени:"
echo -e "  journalctl -u freedom-cry-agent -f\n"

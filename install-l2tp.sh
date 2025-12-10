#!/bin/bash

# ==============================================
# L2TP/IPsec VPN Installer
# System: L2TP Secret auto, IPSec Identifier & PSK sebagai login
# ==============================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Config
CONFIG_DIR="/etc/l2tp-vpn"
DB_FILE="$CONFIG_DIR/database.json"
LOG_FILE="/var/log/l2tp-vpn.log"
BACKUP_DIR="$CONFIG_DIR/backup"
IP_POOL="10.10.30"

# Functions
log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1" | tee -a $LOG_FILE
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a $LOG_FILE
}

header() {
    clear
    echo -e "${PURPLE}"
    echo "========================================"
    echo "    L2TP VPN - Complete System"
    echo "    Auto L2TP Secret + Custom Login"
    echo "========================================"
    echo -e "${NC}"
}

check_root() {
    [ "$EUID" -ne 0 ] && { error "Run as root!"; exit 1; }
}

generate_l2tp_secret() {
    openssl rand -base64 12 | tr -d '=' | tr '+/' 'AZ'
}

generate_id() {
    echo "ID$(shuf -i 10000-99999 -n 1)"
}

install_packages() {
    log "Installing required packages..."
    apt update
    apt install -y strongswan xl2tpd net-tools iptables-persistent curl jq
}

configure_ipsec() {
    log "Configuring IPSec..."
    
    cat > /etc/ipsec.conf << EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn l2tp-psk
    auto=add
    compress=no
    type=transport
    keyexchange=ikev1
    fragmentation=yes
    forceencaps=yes
    ike=aes256-sha1-modp1024!
    esp=aes256-sha1!
    left=%any
    leftid=@vpnserver
    leftsubnet=0.0.0.0/0
    leftfirewall=yes
    right=%any
    rightid=%any
    rightauth=psk
    rightsourceip=${IP_POOL}.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    dpdaction=clear
    dpddelay=300s
    rekey=no
EOF

    # IPSec secrets file
    cat > /etc/ipsec.secrets << EOF
# Format: CLIENT_ID %any : PSK "CLIENT_PSK"
EOF
    chmod 600 /etc/ipsec.secrets
}

configure_xl2tpd() {
    log "Configuring xl2tpd..."
    
    cat > /etc/xl2tpd/xl2tpd.conf << EOF
[global]
ipsec saref = yes
listen-addr = 0.0.0.0

[lns default]
ip range = ${IP_POOL}.100-${IP_POOL}.200
local ip = ${IP_POOL}.1
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
ppp debug = no
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

    cat > /etc/ppp/options.xl2tpd << EOF
ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 8.8.4.4
noccp
auth
crtscts
idle 1800
mtu 1280
mru 1280
lock
lcp-echo-failure 10
lcp-echo-interval 60
connect-delay 5000
EOF

    # L2TP secrets file
    cat > /etc/xl2tpd/l2tp-secrets << EOF
# L2TP Secrets for all clients
* * $(generate_l2tp_secret) *
EOF
    chmod 600 /etc/xl2tpd/l2tp-secrets
}

setup_firewall() {
    log "Setting up firewall..."
    
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p
    
    iptables -t nat -A POSTROUTING -s ${IP_POOL}.0/24 -o $(ip route | grep default | awk '{print $5}') -j MASQUERADE
    iptables -A FORWARD -s ${IP_POOL}.0/24 -j ACCEPT
    iptables -A FORWARD -d ${IP_POOL}.0/24 -j ACCEPT
    
    iptables -A INPUT -p udp --dport 500 -j ACCEPT
    iptables -A INPUT -p udp --dport 4500 -j ACCEPT
    iptables -A INPUT -p udp --dport 1701 -j ACCEPT
    
    netfilter-persistent save
}

create_management_system() {
    log "Creating management system..."
    
    mkdir -p $CONFIG_DIR $BACKUP_DIR
    
    # Initialize database
    if [ ! -f "$DB_FILE" ]; then
        cat > "$DB_FILE" << EOF
{
  "server": {
    "ip": "",
    "l2tp_secret": "$(generate_l2tp_secret)"
  },
  "clients": []
}
EOF
    fi
    
    # Update server IP
    SERVER_IP=$(curl -s ifconfig.me)
    jq ".server.ip = \"$SERVER_IP\"" "$DB_FILE" > "$DB_FILE.tmp" && mv "$DB_FILE.tmp" "$DB_FILE"
    
    # Update L2TP secret
    L2TP_SECRET=$(generate_l2tp_secret)
    jq ".server.l2tp_secret = \"$L2TP_SECRET\"" "$DB_FILE" > "$DB_FILE.tmp" && mv "$DB_FILE.tmp" "$DB_FILE"
    
    # Update L2TP secrets file
    echo "* * $L2TP_SECRET *" > /etc/xl2tpd/l2tp-secrets
}

create_management_scripts() {
    # Create add-client script
    cat > /usr/local/bin/l2tp-add << 'EOF'
#!/bin/bash

CONFIG_DIR="/etc/l2tp-vpn"
DB_FILE="$CONFIG_DIR/database.json"
SERVER_IP=$(curl -s ifconfig.me)

# Colors
G='\033[0;32m'
Y='\033[1;33m'
R='\033[0;31m'
B='\033[0;34m'
N='\033[0m'

show_help() {
    echo "Usage: l2tp-add [options]"
    echo ""
    echo "Options:"
    echo "  --id IDENTIFIER      IPSec Identifier (username)"
    echo "  --psk PASSWORD       IPSec Pre-shared Key (password)"
    echo "  --days DAYS          Expiry in days (default: 30)"
    echo "  --limit LIMIT        Max IP connections (default: 2)"
    echo "  --name NAME          Client name/description"
    echo "  --auto               Auto generate everything"
    echo "  -h, --help          Show this help"
}

generate_id() {
    echo "CLIENT$(shuf -i 1000-9999 -n 1)"
}

generate_psk() {
    openssl rand -base64 16 | tr -d '=' | tr '+/' 'AZ'
}

# Default values
DAYS=30
LIMIT=2
AUTO=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --id)
            IDENTIFIER="$2"
            shift 2
            ;;
        --psk)
            PSK="$2"
            shift 2
            ;;
        --days)
            DAYS="$2"
            shift 2
            ;;
        --limit)
            LIMIT="$2"
            shift 2
            ;;
        --name)
            NAME="$2"
            shift 2
            ;;
        --auto)
            AUTO=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Auto mode
if [ "$AUTO" = true ]; then
    IDENTIFIER=$(generate_id)
    PSK=$(generate_psk)
    NAME="Auto Generated"
fi

# Validate required fields
if [ -z "$IDENTIFIER" ] || [ -z "$PSK" ]; then
    echo -e "${R}Error: Identifier and PSK are required!${N}"
    echo -e "Use --id and --psk options or --auto"
    exit 1
fi

# Check if identifier exists
if jq -e ".clients[] | select(.identifier == \"$IDENTIFIER\")" "$DB_FILE" > /dev/null; then
    echo -e "${R}Error: Identifier '$IDENTIFIER' already exists!${N}"
    exit 1
fi

# Calculate expiry
if [ "$DAYS" -eq 0 ]; then
    EXPIRE="never"
else
    EXPIRE=$(date -d "+$DAYS days" +%Y-%m-%d)
fi

# Get L2TP secret
L2TP_SECRET=$(jq -r '.server.l2tp_secret' "$DB_FILE")

# Add to IPSec secrets
echo "$IDENTIFIER %any : PSK \"$PSK\"" >> /etc/ipsec.secrets

# Create client data
CLIENT_DATA=$(jq -n \
    --arg id "$IDENTIFIER" \
    --arg psk "$PSK" \
    --arg name "${NAME:-$IDENTIFIER}" \
    --arg expire "$EXPIRE" \
    --argjson limit "$LIMIT" \
    --arg created "$(date +%Y-%m-%d)" \
    '{
        identifier: $id,
        psk: $psk,
        name: $name,
        created: $created,
        expire: $expire,
        limit: $limit,
        status: "active",
        last_used: null,
        ips: []
    }')

# Add to database
jq ".clients += [$CLIENT_DATA]" "$DB_FILE" > "$DB_FILE.tmp"
mv "$DB_FILE.tmp" "$DB_FILE"

# Create client config file
CLIENT_FILE="$CONFIG_DIR/clients/$IDENTIFIER.conf"
mkdir -p "$CONFIG_DIR/clients"

cat > "$CLIENT_FILE" << CONFIG
========================================
L2TP/IPsec VPN Configuration
========================================
Client: ${NAME:-$IDENTIFIER}
Created: $(date +%Y-%m-%d)
Expires: $EXPIRE
IP Limit: $LIMIT concurrent connections

=== VPN Settings ===
Server Address: $SERVER_IP
L2TP Secret: $L2TP_SECRET (shared for all clients)
IPSec Identifier: $IDENTIFIER
IPSec Pre-shared Key: $PSK

=== Client Configuration ===
For Android/iOS/Windows:

1. VPN Type: L2TP/IPSec PSK
2. Server: $SERVER_IP
3. L2TP Secret: $L2TP_SECRET
4. IPSec Identifier: $IDENTIFIER
5. IPSec Pre-shared Key: $PSK
6. Username: [leave empty]
7. Password: [leave empty]

=== Notes ===
• L2TP Secret is shared among all clients
• IPSec Identifier & PSK are your login credentials
• Open ports: UDP 500, 4500, 1701
========================================
CONFIG

# Restart services
systemctl restart ipsec
systemctl restart xl2tpd

# Display results
echo -e "${G}========================================${N}"
echo -e "${G}CLIENT ADDED SUCCESSFULLY${N}"
echo -e "${G}========================================${N}"
echo -e "${Y}Server Address:${N} $SERVER_IP"
echo -e "${Y}L2TP Secret:${N} $L2TP_SECRET"
echo -e "${Y}IPSec Identifier:${N} $IDENTIFIER"
echo -e "${Y}IPSec PSK:${N} $PSK"
echo -e "${Y}Expires:${N} $EXPIRE"
echo -e "${Y}IP Limit:${N} $LIMIT"
echo -e "${G}========================================${N}"
echo -e "Config saved: $CLIENT_FILE"
echo -e "${G}========================================${N}"
EOF
    chmod +x /usr/local/bin/l2tp-add

    # Create list script
    cat > /usr/local/bin/l2tp-list << 'EOF'
#!/bin/bash

CONFIG_DIR="/etc/l2tp-vpn"
DB_FILE="$CONFIG_DIR/database.json"

# Colors
G='\033[0;32m'
Y='\033[1;33m'
R='\033[0;31m'
B='\033[0;34m'
N='\033[0m'

TODAY=$(date +%Y-%m-%d)

echo -e "${B}========================================${N}"
echo -e "${B}L2TP VPN CLIENTS LIST${N}"
echo -e "${B}========================================${N}"

# Server info
SERVER_IP=$(jq -r '.server.ip' "$DB_FILE")
L2TP_SECRET=$(jq -r '.server.l2tp_secret' "$DB_FILE")

echo -e "${Y}Server Information:${N}"
echo -e "IP Address: $SERVER_IP"
echo -e "L2TP Secret: $L2TP_SECRET"
echo ""

# Clients list
TOTAL=$(jq '.clients | length' "$DB_FILE")
ACTIVE=0
EXPIRED=0

echo -e "${Y}Active Clients:${N}"
echo -e "${G}No.  Identifier       Name            Expires     Limit  Status${N}"
echo -e "------------------------------------------------------------"

i=1
jq -r '.clients[] | "\(.identifier)|\(.name)|\(.expire)|\(.limit)|\(.status)"' "$DB_FILE" | while IFS='|' read -r id name expire limit status; do
    # Check expiry
    if [ "$expire" != "never" ] && [ "$status" = "active" ]; then
        if [ "$(date -d "$expire" +%s)" -lt "$(date -d "$TODAY" +%s)" ]; then
            status="expired"
            jq "(.clients[] | select(.identifier == \"$id\") | .status) = \"expired\"" "$DB_FILE" > "$DB_FILE.tmp"
            mv "$DB_FILE.tmp" "$DB_FILE"
        fi
    fi
    
    # Status color
    if [ "$status" = "active" ]; then
        STATUS_COLOR="${G}Active${N}"
        ACTIVE=$((ACTIVE + 1))
        
        # Days left
        if [ "$expire" != "never" ]; then
            DAYS_LEFT=$(( ($(date -d "$expire" +%s) - $(date -d "$TODAY" +%s)) / 86400 ))
            if [ $DAYS_LEFT -lt 0 ]; then
                EXPIRE_DISPLAY="${R}Expired${N}"
            elif [ $DAYS_LEFT -lt 7 ]; then
                EXPIRE_DISPLAY="${Y}${DAYS_LEFT}d${N}"
            else
                EXPIRE_DISPLAY="${G}${DAYS_LEFT}d${N}"
            fi
        else
            EXPIRE_DISPLAY="${G}Never${N}"
        fi
    else
        STATUS_COLOR="${R}Expired${N}"
        EXPIRED=$((EXPIRED + 1))
        EXPIRE_DISPLAY="${R}Expired${N}"
    fi
    
    printf "${B}%-4s${N} ${Y}%-16s${N} %-14s %-11s ${G}%-6s${N} %s\n" \
        "$i" "$id" "$name" "$EXPIRE_DISPLAY" "$limit" "$STATUS_COLOR"
    i=$((i + 1))
done

echo ""
echo -e "${Y}Summary:${N}"
echo -e "Total Clients: $TOTAL"
echo -e "Active: $ACTIVE"
echo -e "Expired: $EXPIRED"

# Online users
echo ""
echo -e "${Y}Online Users:${N}"
ONLINE_COUNT=0
if [ -f "/var/run/xl2tpd/l2tp-control" ]; then
    echo -e "${G}IP Address       | Identifier${N}"
    echo -e "-----------------|------------"
    
    # Try to get connected clients
    last | grep ppp | awk '{print $1, $3}' | tr -d '()' | while read id ip; do
        if jq -e ".clients[] | select(.identifier == \"$id\")" "$DB_FILE" > /dev/null; then
            echo -e "$ip       | $id"
            ONLINE_COUNT=$((ONLINE_COUNT + 1))
        fi
    done
fi

if [ $ONLINE_COUNT -eq 0 ]; then
    echo -e "${R}No users online${N}"
fi

echo -e "${B}========================================${N}"
EOF
    chmod +x /usr/local/bin/l2tp-list

    # Create delete script
    cat > /usr/local/bin/l2tp-del << 'EOF'
#!/bin/bash

CONFIG_DIR="/etc/l2tp-vpn"
DB_FILE="$CONFIG_DIR/database.json"

# Colors
G='\033[0;32m'
R='\033[0;31m'
Y='\033[1;33m'
N='\033[0m'

if [ $# -eq 0 ]; then
    echo "Usage: l2tp-del <identifier>"
    echo "       l2tp-del --all-expired"
    echo "       l2tp-del --all"
    exit 1
fi

if [ "$1" = "--all-expired" ]; then
    echo -e "${Y}Deleting all expired clients...${N}"
    
    # Get expired clients
    EXPIRED=$(jq -r '.clients[] | select(.status == "expired") | .identifier' "$DB_FILE")
    
    if [ -z "$EXPIRED" ]; then
        echo -e "${G}No expired clients found${N}"
        exit 0
    fi
    
    COUNT=0
    echo "$EXPIRED" | while read id; do
        # Remove from ipsec.secrets
        sed -i "/^$id /d" /etc/ipsec.secrets
        
        # Remove config file
        rm -f "$CONFIG_DIR/clients/$id.conf"
        
        COUNT=$((COUNT + 1))
    done
    
    # Remove from database
    jq '.clients = (.clients | map(select(.status != "expired")))' "$DB_FILE" > "$DB_FILE.tmp"
    mv "$DB_FILE.tmp" "$DB_FILE"
    
    echo -e "${G}Deleted $COUNT expired clients${N}"
    exit 0
fi

if [ "$1" = "--all" ]; then
    echo -e "${R}WARNING: This will delete ALL clients!${N}"
    read -p "Type 'YES' to confirm: " confirm
    if [ "$confirm" != "YES" ]; then
        echo -e "${Y}Cancelled${N}"
        exit 0
    fi
    
    # Backup
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    cp /etc/ipsec.secrets /etc/ipsec.secrets.backup.$TIMESTAMP
    
    # Clear ipsec.secrets
    echo "# Format: CLIENT_ID %any : PSK \"CLIENT_PSK\"" > /etc/ipsec.secrets
    
    # Clear database
    jq '.clients = []' "$DB_FILE" > "$DB_FILE.tmp"
    mv "$DB_FILE.tmp" "$DB_FILE"
    
    # Remove config files
    rm -f "$CONFIG_DIR/clients"/*.conf
    
    echo -e "${G}All clients deleted${N}"
    exit 0
fi

IDENTIFIER="$1"

# Check if exists
if ! jq -e ".clients[] | select(.identifier == \"$IDENTIFIER\")" "$DB_FILE" > /dev/null; then
    echo -e "${R}Client '$IDENTIFIER' not found!${N}"
    exit 1
fi

# Remove from ipsec.secrets
sed -i "/^$IDENTIFIER /d" /etc/ipsec.secrets

# Remove from database
jq "del(.clients[] | select(.identifier == \"$IDENTIFIER\"))" "$DB_FILE" > "$DB_FILE.tmp"
mv "$DB_FILE.tmp" "$DB_FILE"

# Remove config file
rm -f "$CONFIG_DIR/clients/$IDENTIFIER.conf"

# Restart services
systemctl restart ipsec

echo -e "${G}Client '$IDENTIFIER' deleted successfully${N}"
EOF
    chmod +x /usr/local/bin/l2tp-del

    # Create limit script
    cat > /usr/local/bin/l2tp-limit << 'EOF'
#!/bin/bash

CONFIG_DIR="/etc/l2tp-vpn"
DB_FILE="$CONFIG_DIR/database.json"

# Colors
G='\033[0;32m'
Y='\033[1;33m'
R='\033[0;31m'
N='\033[0m'

show_help() {
    echo "Usage: l2tp-limit [command]"
    echo ""
    echo "Commands:"
    echo "  set <id> <limit>      Set IP limit for client"
    echo "  get <id>              Get current limit"
    echo "  reset <id>            Reset to default (2)"
    echo "  list                  Show all limits"
    echo "  --help                Show this help"
}

case "$1" in
    set)
        if [ $# -ne 3 ]; then
            echo "Usage: l2tp-limit set <identifier> <limit>"
            exit 1
        fi
        
        ID="$2"
        LIMIT="$3"
        
        if ! [[ "$LIMIT" =~ ^[0-9]+$ ]]; then
            echo -e "${R}Limit must be a number!${N}"
            exit 1
        fi
        
        if ! jq -e ".clients[] | select(.identifier == \"$ID\")" "$DB_FILE" > /dev/null; then
            echo -e "${R}Client not found!${N}"
            exit 1
        fi
        
        jq "(.clients[] | select(.identifier == \"$ID\") | .limit) = $LIMIT" "$DB_FILE" > "$DB_FILE.tmp"
        mv "$DB_FILE.tmp" "$DB_FILE"
        
        echo -e "${G}IP limit for $ID set to $LIMIT${N}"
        ;;
        
    get)
        if [ $# -ne 2 ]; then
            echo "Usage: l2tp-limit get <identifier>"
            exit 1
        fi
        
        ID="$2"
        LIMIT=$(jq -r ".clients[] | select(.identifier == \"$ID\") | .limit" "$DB_FILE" 2>/dev/null)
        
        if [ -z "$LIMIT" ] || [ "$LIMIT" = "null" ]; then
            echo -e "${R}Client not found!${N}"
            exit 1
        fi
        
        echo -e "${Y}$ID limit:${N} $LIMIT"
        ;;
        
    reset)
        if [ $# -ne 2 ]; then
            echo "Usage: l2tp-limit reset <identifier>"
            exit 1
        fi
        
        ID="$2"
        
        if ! jq -e ".clients[] | select(.identifier == \"$ID\")" "$DB_FILE" > /dev/null; then
            echo -e "${R}Client not found!${N}"
            exit 1
        fi
        
        jq "(.clients[] | select(.identifier == \"$ID\") | .limit) = 2" "$DB_FILE" > "$DB_FILE.tmp"
        mv "$DB_FILE.tmp" "$DB_FILE"
        
        echo -e "${G}Reset $ID limit to default (2)${N}"
        ;;
        
    list)
        echo -e "${Y}Client IP Limits:${N}"
        echo ""
        
        jq -r '.clients[] | "\(.identifier) \(.limit)"' "$DB_FILE" | while read id limit; do
            # Check current connections
            COUNT=$(last | grep ppp | grep "^$id " | wc -l 2>/dev/null || echo 0)
            
            if [ "$COUNT" -gt "$limit" ]; then
                echo -e "${R}$id: $COUNT/$limit (OVER)${N}"
            elif [ "$COUNT" -eq "$limit" ]; then
                echo -e "${Y}$id: $COUNT/$limit (AT LIMIT)${N}"
            else
                echo -e "${G}$id: $COUNT/$limit${N}"
            fi
        done
        ;;
        
    --help|-h)
        show_help
        ;;
        
    *)
        echo "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
EOF
    chmod +x /usr/local/bin/l2tp-limit

    # Create renew script
    cat > /usr/local/bin/l2tp-renew << 'EOF'
#!/bin/bash

CONFIG_DIR="/etc/l2tp-vpn"
DB_FILE="$CONFIG_DIR/database.json"

# Colors
G='\033[0;32m'
Y='\033[1;33m'
R='\033[0;31m'
N='\033[0m'

if [ $# -lt 2 ]; then
    echo "Usage: l2tp-renew <identifier> <days>"
    echo "       l2tp-renew <identifier> never (for no expiry)"
    exit 1
fi

IDENTIFIER="$1"
DAYS="$2"
TODAY=$(date +%Y-%m-%d)

# Check if client exists
if ! jq -e ".clients[] | select(.identifier == \"$IDENTIFIER\")" "$DB_FILE" > /dev/null; then
    echo -e "${R}Client '$IDENTIFIER' not found!${N}"
    exit 1
fi

# Calculate new expiry
if [ "$DAYS" = "never" ]; then
    NEW_EXPIRE="never"
else
    if ! [[ "$DAYS" =~ ^[0-9]+$ ]]; then
        echo -e "${R}Days must be a number!${N}"
        exit 1
    fi
    
    # Get current expiry
    CURRENT=$(jq -r ".clients[] | select(.identifier == \"$IDENTIFIER\") | .expire" "$DB_FILE")
    
    if [ "$CURRENT" = "never" ]; then
        NEW_EXPIRE="never"
    else
        # If expired, renew from today
        CURRENT_TS=$(date -d "$CURRENT" +%s 2>/dev/null || date -d "$TODAY" +%s)
        TODAY_TS=$(date -d "$TODAY" +%s)
        
        if [ $CURRENT_TS -lt $TODAY_TS ]; then
            NEW_EXPIRE=$(date -d "+$DAYS days" +%Y-%m-%d)
        else
            NEW_EXPIRE=$(date -d "$CURRENT + $DAYS days" +%Y-%m-%d)
        fi
    fi
fi

# Update database
jq "(.clients[] | select(.identifier == \"$IDENTIFIER\") | .expire) = \"$NEW_EXPIRE\"" \
    "$DB_FILE" > "$DB_FILE.tmp"
mv "$DB_FILE.tmp" "$DB_FILE"

jq "(.clients[] | select(.identifier == \"$IDENTIFIER\") | .status) = \"active\"" \
    "$DB_FILE" > "$DB_FILE.tmp"
mv "$DB_FILE.tmp" "$DB_FILE"

echo -e "${G}Client '$IDENTIFIER' renewed until $NEW_EXPIRE${N}"
EOF
    chmod +x /usr/local/bin/l2tp-renew

    # Create menu script
    cat > /usr/local/bin/l2tp-menu << 'EOF'
#!/bin/bash

# Colors
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
B='\033[0;34m'
P='\033[0;35m'
N='\033[0m'

CONFIG_DIR="/etc/l2tp-vpn"
DB_FILE="$CONFIG_DIR/database.json"

show_header() {
    clear
    echo -e "${P}"
    echo "╔══════════════════════════════════════╗"
    echo "║      L2TP VPN Management Menu       ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${N}"
    
    SERVER_IP=$(jq -r '.server.ip' "$DB_FILE" 2>/dev/null || echo "NOT SET")
    echo -e "${Y}Server:${N} $SERVER_IP"
    echo ""
}

show_menu() {
    show_header
    echo -e "${B}Main Menu:${N}"
    echo -e "${G}[1]${N} Add New Client"
    echo -e "${G}[2]${N} List All Clients"
    echo -e "${G}[3]${N} Delete Client"
    echo -e "${G}[4]${N} Manage IP Limits"
    echo -e "${G}[5]${N} Renew/Extend Client"
    echo -e "${G}[6]${N} View Server Status"
    echo -e "${G}[7]${N} Change L2TP Secret"
    echo -e "${G}[8]${N} Backup & Restore"
    echo -e "${G}[9]${N} View Connection Logs"
    echo -e "${R}[0]${N} Exit"
    echo -e "${Y}══════════════════════════════════════${N}"
    echo -n -e "${B}Choose [0-9]: ${N}"
}

add_client_menu() {
    echo -e "${Y}══════════════════════════════════════${N}"
    echo -e "${B}ADD NEW CLIENT${N}"
    echo -e "${Y}══════════════════════════════════════${N}"
    
    echo -e "${G}[1]${N} Auto Generate (Recommended)"
    echo -e "${G}[2]${N} Manual Configuration"
    echo -e "${G}[3]${N} Bulk Create"
    echo -n -e "${B}Choose [1-3]: ${N}"
    
    read choice
    case $choice in
        1)
            read -p "Days to expire [30]: " days
            read -p "IP Limit [2]: " limit
            read -p "Client name [Auto]: " name
            
            days=${days:-30}
            limit=${limit:-2}
            
            if [ -z "$name" ]; then
                l2tp-add --auto --days "$days" --limit "$limit"
            else
                l2tp-add --auto --days "$days" --limit "$limit" --name "$name"
            fi
            ;;
        2)
            read -p "IPSec Identifier: " id
            read -p "IPSec PSK (empty for auto): " psk
            read -p "Days to expire [30]: " days
            read -p "IP Limit [2]: " limit
            read -p "Client name: " name
            
            days=${days:-30}
            limit=${limit:-2}
            
            if [ -z "$psk" ]; then
                psk=$(openssl rand -base64 16 | tr -d '=' | tr '+/' 'AZ')
            fi
            
            l2tp-add --id "$id" --psk "$psk" --days "$days" --limit "$limit" --name "$name"
            ;;
        3)
            read -p "Number of clients: " count
            read -p "Days to expire [30]: " days
            read -p "IP Limit [2]: " limit
            
            days=${days:-30}
            limit=${limit:-2}
            
            for i in $(seq 1 $count); do
                echo -e "${Y}Creating client $i/$count...${N}"
                l2tp-add --auto --days "$days" --limit "$limit" --name "Client$i"
                echo ""
            done
            ;;
    esac
    
    read -p "Press Enter to continue..."
}

delete_client_menu() {
    echo -e "${Y}══════════════════════════════════════${N}"
    echo -e "${B}DELETE CLIENT${N}"
    echo -e "${Y}══════════════════════════════════════${N}"
    
    l2tp-list | head -40
    
    echo ""
    echo -e "${G}[1]${N} Delete by identifier"
    echo -e "${G}[2]${N} Delete all expired"
    echo -e "${R}[3]${N} Delete ALL clients"
    echo -n -e "${B}Choose [1-3]: ${N}"
    
    read choice
    case $choice in
        1)
            read -p "Enter identifier to delete: " id
            if [ -n "$id" ]; then
                l2tp-del "$id"
            fi
            ;;
        2)
            l2tp-del --all-expired
            ;;
        3)
            l2tp-del --all
            ;;
    esac
    
    read -p "Press Enter to continue..."
}

limit_menu() {
    echo -e "${Y}══════════════════════════════════════${N}"
    echo -e "${B}MANAGE IP LIMITS${N}"
    echo -e "${Y}══════════════════════════════════════${N}"
    
    echo -e "${G}[1]${N} Set IP limit"
    echo -e "${G}[2]${N} View all limits"
    echo -e "${G}[3]${N} Reset limit"
    echo -n -e "${B}Choose [1-3]: ${N}"
    
    read choice
    case $choice in
        1)
            l2tp-list | head -30
            echo ""
            read -p "Identifier: " id
            read -p "New IP limit: " limit
            if [ -n "$id" ] && [ -n "$limit" ]; then
                l2tp-limit set "$id" "$limit"
            fi
            ;;
        2)
            l2tp-limit list
            ;;
        3)
            l2tp-list | head -30
            echo ""
            read -p "Identifier: " id
            if [ -n "$id" ]; then
                l2tp-limit reset "$id"
            fi
            ;;
    esac
    
    read -p "Press Enter to continue..."
}

renew_menu() {
    echo -e "${Y}══════════════════════════════════════${N}"
    echo -e "${B}RENEW/EXTEND CLIENT${N}"
    echo -e "${Y}══════════════════════════════════════${N}"
    
    l2tp-list | head -30
    
    echo ""
    read -p "Identifier: " id
    if [ -z "$id" ]; then
        return
    fi
    
    read -p "Add days (or 'never'): " days
    if [ -n "$days" ]; then
        l2tp-renew "$id" "$days"
    fi
    
    read -p "Press Enter to continue..."
}

server_status_menu() {
    echo -e "${Y}══════════════════════════════════════${N}"
    echo -e "${B}SERVER STATUS${N}"
    echo -e "${Y}══════════════════════════════════════${N}"
    
    SERVER_IP=$(curl -s ifconfig.me)
    L2TP_SECRET=$(jq -r '.server.l2tp_secret' "$DB_FILE" 2>/dev/null)
    
    echo -e "${G}Server Information:${N}"
    echo -e "IP Address: $SERVER_IP"
    echo -e "L2TP Secret: $L2TP_SECRET"
    echo -e "Hostname: $(hostname)"
    echo -e "OS: $(lsb_release -ds)"
    echo ""
    
    echo -e "${G}Service Status:${N}"
    if systemctl is-active --quiet ipsec; then
        echo -e "IPSec: ${G}RUNNING${N}"
    else
        echo -e "IPSec: ${R}STOPPED${N}"
    fi
    
    if systemctl is-active --quiet xl2tpd; then
        echo -e "L2TP: ${G}RUNNING${N}"
    else
        echo -e "L2TP: ${R}STOPPED${N}"
    fi
    echo ""
    
    echo -e "${G}Port Status:${N}"
    for port in 500 4500 1701; do
        if netstat -tuln 2>/dev/null | grep -q ":$port"; then
            echo -e "UDP $port: ${G}OPEN${N}"
        else
            echo -e "UDP $port: ${R}CLOSED${N}"
        fi
    done
    echo ""
    
    echo -e "${G}Statistics:${N}"
    TOTAL=$(jq '.clients | length' "$DB_FILE" 2>/dev/null || echo "0")
    ONLINE=$(last | grep ppp | wc -l 2>/dev/null || echo "0")
    echo -e "Total Clients: $TOTAL"
    echo -e "Online Now: $ONLINE"
    
    echo -e "${Y}══════════════════════════════════════${N}"
    read -p "Press Enter to continue..."
}

change_l2tp_secret() {
    echo -e "${Y}══════════════════════════════════════${N}"
    echo -e "${B}CHANGE L2TP SECRET${N}"
    echo -e "${Y}══════════════════════════════════════${N}"
    
    OLD_SECRET=$(jq -r '.server.l2tp_secret' "$DB_FILE")
    echo -e "Current L2TP Secret: ${Y}$OLD_SECRET${N}"
    echo ""
    
    read -p "Generate new L2TP Secret? (y/n): " choice
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        NEW_SECRET=$(openssl rand -base64 12 | tr -d '=' | tr '+/' 'AZ')
        
        # Update database
        jq ".server.l2tp_secret = \"$NEW_SECRET\"" "$DB_FILE" > "$DB_FILE.tmp"
        mv "$DB_FILE.tmp" "$DB_FILE"
        
        # Update config file
        echo "* * $NEW_SECRET *" > /etc/xl2tpd/l2tp-secrets
        
        # Restart service
        systemctl restart xl2tpd
        
        echo -e "${G}New L2TP Secret: $NEW_SECRET${N}"
        echo -e "${Y}All clients need to update their L2TP Secret!${N}"
    fi
    
    read -p "Press Enter to continue..."
}

backup_menu() {
    echo -e "${Y}══════════════════════════════════════${N}"
    echo -e "${B}BACKUP & RESTORE${N}"
    echo -e "${Y}══════════════════════════════════════${N}"
    
    echo -e "${G}[1]${N} Create backup"
    echo -e "${G}[2]${N} Restore backup"
    echo -e "${G}[3]${N} List backups"
    echo -n -e "${B}Choose [1-3]: ${N}"
    
    read choice
    case $choice in
        1)
            TIMESTAMP=$(date +%Y%m%d_%H%M%S)
            BACKUP_FILE="$CONFIG_DIR/backup/backup_$TIMESTAMP.tar.gz"
            
            tar -czf "$BACKUP_FILE" \
                /etc/ipsec.* \
                /etc/xl2tpd \
                /etc/ppp \
                "$CONFIG_DIR" \
                /etc/iptables/rules.v4 2>/dev/null
            
            echo -e "${G}Backup created: $BACKUP_FILE${N}"
            ;;
        2)
            echo -e "${Y}Available backups:${N}"
            ls -lh "$CONFIG_DIR/backup/"*.tar.gz 2>/dev/null | nl
            
            read -p "Select backup number: " num
            BACKUP_FILE=$(ls "$CONFIG_DIR/backup/"*.tar.gz 2>/dev/null | sed -n "${num}p")
            
            if [ -f "$BACKUP_FILE" ]; then
                echo -e "${Y}Restoring...${N}"
                tar -xzf "$BACKUP_FILE" -C /
                systemctl restart ipsec xl2tpd
                echo -e "${G}Restore completed!${N}"
            else
                echo -e "${R}Invalid selection!${N}"
            fi
            ;;
        3)
            ls -lh "$CONFIG_DIR/backup/"*.tar.gz 2>/dev/null
            ;;
    esac
    
    read -p "Press Enter to continue..."
}

view_logs() {
    echo -e "${Y}══════════════════════════════════════${N}"
    echo -e "${B}VIEW LOGS${N}"
    echo -e "${Y}══════════════════════════════════════${N}"
    
    echo -e "${G}[1]${N} IPSec logs"
    echo -e "${G}[2]${N} L2TP logs"
    echo -e "${G}[3]${N} Authentication logs"
    echo -e "${G}[4]${N} Real-time monitoring"
    echo -n -e "${B}Choose [1-4]: ${N}"
    
    read choice
    case $choice in
        1)
            journalctl -u ipsec --no-pager -n 30
            ;;
        2)
            journalctl -u xl2tpd --no-pager -n 30
            ;;
        3)
            tail -30 /var/log/auth.log | grep -i ppp
            ;;
        4)
            echo -e "${Y}Real-time monitoring (Ctrl+C to stop)...${N}"
            tail -f /var/log/auth.log | grep -E "(ppp|L2TP|IPSEC)"
            ;;
    esac
    
    read -p "Press Enter to continue..."
}

# Main loop
while true; do
    show_menu
    read choice
    
    case $choice in
        1) add_client_menu ;;
        2) l2tp-list; read -p "Press Enter to continue..." ;;
        3) delete_client_menu ;;
        4) limit_menu ;;
        5) renew_menu ;;
        6) server_status_menu ;;
        7) change_l2tp_secret ;;
        8) backup_menu ;;
        9) view_logs ;;
        0)
            echo -e "${G}Goodbye!${N}"
            exit 0
            ;;
        *)
            echo -e "${R}Invalid choice!${N}"
            sleep 1
            ;;
    esac
done
EOF
    chmod +x /usr/local/bin/l2tp-menu
}

start_services() {
    log "Starting services..."
    systemctl restart ipsec
    systemctl restart xl2tpd
    systemctl enable ipsec
    systemctl enable xl2tpd
}

show_completion() {
    header
    
    SERVER_IP=$(curl -s ifconfig.me)
    L2TP_SECRET=$(jq -r '.server.l2tp_secret' "$DB_FILE" 2>/dev/null)
    
    echo -e "${G}========================================${N}"
    echo -e "${G}INSTALLATION COMPLETE!${N}"
    echo -e "${G}========================================${N}"
    echo ""
    
    echo -e "${Y}SERVER INFORMATION:${N}"
    echo -e "IP Address: $SERVER_IP"
    echo -e "L2TP Secret: $L2TP_SECRET"
    echo -e "Ports: UDP 500, 4500, 1701"
    echo ""
    
    echo -e "${Y}AVAILABLE COMMANDS:${N}"
    echo -e "1. ${G}l2tp-menu${N}    - Main management menu"
    echo -e "2. ${G}l2tp-add${N}     - Add new client"
    echo -e "3. ${G}l2tp-list${N}    - List all clients"
    echo -e "4. ${G}l2tp-del${N}     - Delete client"
    echo -e "5. ${G}l2tp-limit${N}   - Manage IP limits"
    echo -e "6. ${G}l2tp-renew${N}   - Renew client"
    echo ""
    
    echo -e "${Y}QUICK START:${N}"
    echo -e "Create test client: ${G}l2tp-add --auto --days 7 --limit 2${N}"
    echo ""
    
    echo -e "${R}IMPORTANT:${N}"
    echo -e "1. Open firewall ports: UDP 500, 4500, 1701"
    echo -e "2. Share L2TP Secret with all clients: $L2TP_SECRET"
    echo -e "3. Each client gets unique IPSec Identifier & PSK"
    echo -e "${G}========================================${N}"
}

# Main installation
main() {
    header
    check_root
    install_packages
    configure_ipsec
    configure_xl2tpd
    setup_firewall
    create_management_system
    create_management_scripts
    start_services
    show_completion
}

# Run
if [ "$1" = "uninstall" ]; then
    echo -e "${R}Uninstalling...${N}"
    systemctl stop ipsec xl2tpd
    apt remove -y strongswan xl2tpd
    rm -f /usr/local/bin/l2tp-*
    rm -rf /etc/l2tp-vpn
    echo -e "${G}Uninstall complete!${N}"
else
    main
fi
#!/bin/bash

# ==============================================
# L2TP/IPsec VPN Auto Installer
# Menu Utama: "l2tp"
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
IP_POOL="10.10.50"
DEFAULT_DAYS=30
DEFAULT_LIMIT=2

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
    echo "=========================================="
    echo "    L2TP/IPsec VPN - Complete Installer"
    echo "    Menu: 'l2tp'"
    echo "=========================================="
    echo -e "${NC}"
}

check_root() {
    [ "$EUID" -ne 0 ] && { error "Run as root!"; exit 1; }
}

generate_string() {
    length=$1
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c $length
}

install_packages() {
    log "Installing packages..."
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
    
    mkdir -p $CONFIG_DIR $BACKUP_DIR "$CONFIG_DIR/clients"
    
    # Initialize database
    if [ ! -f "$DB_FILE" ]; then
        cat > "$DB_FILE" << EOF
{
  "server": {
    "ip": "",
    "created": "$(date +%Y-%m-%d)"
  },
  "clients": []
}
EOF
    fi
    
    # Update server IP
    SERVER_IP=$(curl -s ifconfig.me)
    jq ".server.ip = \"$SERVER_IP\"" "$DB_FILE" > "$DB_FILE.tmp" && mv "$DB_FILE.tmp" "$DB_FILE"
}

# ==============================================
# CREATE MAIN MENU SCRIPT: "l2tp"
# ==============================================
create_main_menu() {
    cat > /usr/local/bin/l2tp << 'EOF'
#!/bin/bash

# Colors
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
B='\033[0;34m'
P='\033[0;35m'
C='\033[0;36m'
N='\033[0m'

CONFIG_DIR="/etc/l2tp-vpn"
DB_FILE="$CONFIG_DIR/database.json"

generate_string() {
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c $1
}

show_header() {
    clear
    echo -e "${P}"
    echo "╔══════════════════════════════════════════╗"
    echo "║       L2TP/IPsec VPN Manager            ║"
    echo "║       Type 'l2tp' to open menu          ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${N}"
    
    SERVER_IP=$(jq -r '.server.ip' "$DB_FILE" 2>/dev/null || curl -s ifconfig.me)
    echo -e "${C}Server IP:${N} $SERVER_IP"
    echo ""
}

show_menu() {
    show_header
    echo -e "${B}MAIN MENU:${N}"
    echo -e "${G}[1]${N}  Buat Akun Baru (Auto)"
    echo -e "${G}[2]${N}  Buat Akun Custom"
    echo -e "${G}[3]${N}  Lihat Semua Akun"
    echo -e "${G}[4]${N}  Lihat Detail Akun"
    echo -e "${G}[5]${N}  Hapus Akun"
    echo -e "${G}[6]${N}  Perpanjang Akun"
    echo -e "${G}[7]${N}  Atur Limit IP"
    echo -e "${G}[8]${N}  Lihat User Online"
    echo -e "${G}[9]${N}  Status Server"
    echo -e "${G}[10]${N} Backup & Restore"
    echo -e "${G}[11]${N} Ganti Password"
    echo -e "${G}[12]${N} Lihat Logs"
    echo -e "${G}[13]${N} Restart Services"
    echo -e "${G}[14]${N} Test Koneksi"
    echo -e "${R}[0]${N}  Keluar"
    echo -e "${Y}══════════════════════════════════════════${N}"
    echo -n -e "${B}Pilih [0-14]: ${N}"
}

create_auto_account() {
    echo -e "${Y}══════════════════════════════════════════${N}"
    echo -e "${B}BUAT AKUN AUTO GENERATE${N}"
    echo -e "${Y}══════════════════════════════════════════${N}"
    
    read -p "Masa aktif (hari) [30]: " days
    read -p "Limit IP [2]: " limit
    read -p "Nama client [Auto]: " name
    
    days=${days:-30}
    limit=${limit:-2}
    name=${name:-"Client Auto"}
    
    # Generate semua credentials
    USERNAME="user$(shuf -i 1000-9999 -n 1)"
    PASSWORD=$(generate_string 12)
    L2TP_SECRET=$(generate_string 16)
    IPSEC_ID="vpn$(shuf -i 10000-99999 -n 1)"
    IPSEC_PSK=$(generate_string 32)
    
    # Calculate expiry
    if [ "$days" -eq 0 ]; then
        EXPIRE="never"
    else
        EXPIRE=$(date -d "+$days days" +%Y-%m-%d)
    fi
    
    # Add to chap-secrets
    echo "$USERNAME * $PASSWORD *" >> /etc/ppp/chap-secrets
    
    # Add to IPSec secrets
    echo "$IPSEC_ID %any : PSK \"$IPSEC_PSK\"" >> /etc/ipsec.secrets
    
    # Create client data
    CLIENT_DATA=$(jq -n \
        --arg user "$USERNAME" \
        --arg pass "$PASSWORD" \
        --arg id "$IPSEC_ID" \
        --arg psk "$IPSEC_PSK" \
        --arg secret "$L2TP_SECRET" \
        --arg name "$name" \
        --arg expire "$EXPIRE" \
        --argjson limit "$limit" \
        --arg created "$(date +%Y-%m-%d)" \
        '{
            username: $user,
            password: $pass,
            ipsec_id: $id,
            ipsec_psk: $psk,
            l2tp_secret: $secret,
            name: $name,
            created: $created,
            expire: $expire,
            limit: $limit,
            status: "active"
        }')
    
    # Add to database
    jq ".clients += [$CLIENT_DATA]" "$DB_FILE" > "$DB_FILE.tmp"
    mv "$DB_FILE.tmp" "$DB_FILE"
    
    # Create config file
    CLIENT_FILE="$CONFIG_DIR/clients/$USERNAME.conf"
    SERVER_IP=$(jq -r '.server.ip' "$DB_FILE")
    
    cat > "$CLIENT_FILE" << CONFIG
============================================
L2TP/IPsec VPN Configuration
============================================
Client: $name
Created: $(date +%Y-%m-%d)
Expires: $EXPIRE
IP Limit: $limit

=== SERVER ===
Server: $SERVER_IP
Ports: UDP 500, 4500, 1701
DNS: 8.8.8.8, 8.8.4.4

=== LOGIN ===
Username: $USERNAME
Password: $PASSWORD

=== L2TP ===
L2TP Secret: $L2TP_SECRET

=== IPSEC ===
IPSec Identifier: $IPSEC_ID
IPSec Pre-shared Key: $IPSEC_PSK

=== CARA PAKAI ===
Android/iOS:
1. Type: L2TP/IPSec PSK
2. Server: $SERVER_IP
3. Username: $USERNAME
4. Password: $PASSWORD
5. L2TP Secret: $L2TP_SECRET
6. IPSec Identifier: $IPSEC_ID
7. IPSec PSK: $IPSEC_PSK

Windows:
1. VPN Type: L2TP/IPsec with pre-shared key
2. Server: $SERVER_IP
3. Username: $USERNAME
4. Password: $PASSWORD
5. Pre-shared key: $IPSEC_PSK
============================================
CONFIG
    
    # Restart services
    systemctl restart ipsec xl2tpd >/dev/null 2>&1
    
    # Display results
    echo -e "${G}============================================${N}"
    echo -e "${G}AKUN BERHASIL DIBUAT!${N}"
    echo -e "${G}============================================${N}"
    echo ""
    echo -e "${Y}=== SERVER ===${N}"
    echo -e "Server: $SERVER_IP"
    echo ""
    echo -e "${Y}=== LOGIN ===${N}"
    echo -e "Username: $USERNAME"
    echo -e "Password: $PASSWORD"
    echo ""
    echo -e "${Y}=== L2TP ===${N}"
    echo -e "L2TP Secret: $L2TP_SECRET"
    echo ""
    echo -e "${Y}=== IPSEC ===${N}"
    echo -e "IPSec Identifier: $IPSEC_ID"
    echo -e "IPSec PSK: $IPSEC_PSK"
    echo ""
    echo -e "${Y}=== INFO ===${N}"
    echo -e "Expires: $EXPIRE"
    echo -e "IP Limit: $limit"
    echo -e "${G}============================================${N}"
    echo -e "Config: $CLIENT_FILE"
    echo -e "${G}============================================${N}"
    
    read -p "Tekan Enter untuk lanjut..."
}

create_custom_account() {
    echo -e "${Y}══════════════════════════════════════════${N}"
    echo -e "${B}BUAT AKUN CUSTOM${N}"
    echo -e "${Y}══════════════════════════════════════════${N}"
    
    read -p "Username: " USERNAME
    read -p "Password (kosong untuk auto): " PASSWORD
    read -p "L2TP Secret (kosong untuk auto): " L2TP_SECRET
    read -p "IPSec Identifier (kosong untuk auto): " IPSEC_ID
    read -p "IPSec PSK (kosong untuk auto): " IPSEC_PSK
    read -p "Masa aktif (hari) [30]: " days
    read -p "Limit IP [2]: " limit
    read -p "Nama client: " name
    
    days=${days:-30}
    limit=${limit:-2}
    
    # Auto generate jika kosong
    [ -z "$PASSWORD" ] && PASSWORD=$(generate_string 12)
    [ -z "$L2TP_SECRET" ] && L2TP_SECRET=$(generate_string 16)
    [ -z "$IPSEC_ID" ] && IPSEC_ID="vpn$(shuf -i 10000-99999 -n 1)"
    [ -z "$IPSEC_PSK" ] && IPSEC_PSK=$(generate_string 32)
    [ -z "$name" ] && name="$USERNAME"
    
    # Check if username exists
    if jq -e ".clients[] | select(.username == \"$USERNAME\")" "$DB_FILE" > /dev/null; then
        echo -e "${R}Username sudah ada!${N}"
        read -p "Tekan Enter untuk lanjut..."
        return
    fi
    
    # Check if IPSec ID exists
    if jq -e ".clients[] | select(.ipsec_id == \"$IPSEC_ID\")" "$DB_FILE" > /dev/null; then
        echo -e "${R}IPSec Identifier sudah ada!${N}"
        read -p "Tekan Enter untuk lanjut..."
        return
    fi
    
    # Calculate expiry
    if [ "$days" -eq 0 ]; then
        EXPIRE="never"
    else
        EXPIRE=$(date -d "+$days days" +%Y-%m-%d)
    fi
    
    # Add to chap-secrets
    echo "$USERNAME * $PASSWORD *" >> /etc/ppp/chap-secrets
    
    # Add to IPSec secrets
    echo "$IPSEC_ID %any : PSK \"$IPSEC_PSK\"" >> /etc/ipsec.secrets
    
    # Create client data
    CLIENT_DATA=$(jq -n \
        --arg user "$USERNAME" \
        --arg pass "$PASSWORD" \
        --arg id "$IPSEC_ID" \
        --arg psk "$IPSEC_PSK" \
        --arg secret "$L2TP_SECRET" \
        --arg name "$name" \
        --arg expire "$EXPIRE" \
        --argjson limit "$limit" \
        --arg created "$(date +%Y-%m-%d)" \
        '{
            username: $user,
            password: $pass,
            ipsec_id: $id,
            ipsec_psk: $psk,
            l2tp_secret: $secret,
            name: $name,
            created: $created,
            expire: $expire,
            limit: $limit,
            status: "active"
        }')
    
    # Add to database
    jq ".clients += [$CLIENT_DATA]" "$DB_FILE" > "$DB_FILE.tmp"
    mv "$DB_FILE.tmp" "$DB_FILE"
    
    # Restart services
    systemctl restart ipsec xl2tpd >/dev/null 2>&1
    
    SERVER_IP=$(jq -r '.server.ip' "$DB_FILE")
    
    echo -e "${G}============================================${N}"
    echo -e "${G}AKUN BERHASIL DIBUAT!${N}"
    echo -e "${G}============================================${N}"
    echo -e "${Y}Server:${N} $SERVER_IP"
    echo -e "${Y}Username:${N} $USERNAME"
    echo -e "${Y}Password:${N} $PASSWORD"
    echo -e "${Y}L2TP Secret:${N} $L2TP_SECRET"
    echo -e "${Y}IPSec Identifier:${N} $IPSEC_ID"
    echo -e "${Y}IPSec PSK:${N} $IPSEC_PSK"
    echo -e "${Y}Expires:${N} $EXPIRE"
    echo -e "${Y}IP Limit:${N} $limit"
    echo -e "${G}============================================${N}"
    
    read -p "Tekan Enter untuk lanjut..."
}

list_accounts() {
    echo -e "${Y}══════════════════════════════════════════${N}"
    echo -e "${B}DAFTAR SEMUA AKUN${N}"
    echo -e "${Y}══════════════════════════════════════════${N}"
    
    TOTAL=$(jq '.clients | length' "$DB_FILE" 2>/dev/null || echo "0")
    
    if [ "$TOTAL" -eq 0 ]; then
        echo -e "${R}Tidak ada akun!${N}"
        read -p "Tekan Enter untuk lanjut..."
        return
    fi
    
    TODAY=$(date +%Y-%m-%d)
    
    echo -e "${G}#   Username       IPSec ID       Expires     Limit  Status${N}"
    echo -e "---------------------------------------------------------------"
    
    i=1
    jq -r '.clients[] | "\(.username)|\(.ipsec_id)|\(.expire)|\(.limit)|\(.status)"' "$DB_FILE" 2>/dev/null | while IFS='|' read -r user id expire limit status; do
        # Check expiry
        if [ "$expire" != "never" ] && [ "$status" = "active" ]; then
            if [ "$(date -d "$expire" +%s 2>/dev/null)" -lt "$(date -d "$TODAY" +%s)" ]; then
                status="expired"
                jq "(.clients[] | select(.username == \"$user\") | .status) = \"expired\"" "$DB_FILE" > "$DB_FILE.tmp"
                mv "$DB_FILE.tmp" "$DB_FILE"
            fi
        fi
        
        # Status color
        if [ "$status" = "active" ]; then
            STATUS_COLOR="${G}Active${N}"
            
            # Days left
            if [ "$expire" != "never" ]; then
                DAYS_LEFT=$(( ($(date -d "$expire" +%s 2>/dev/null) - $(date -d "$TODAY" +%s)) / 86400 ))
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
            EXPIRE_DISPLAY="${R}Expired${N}"
        fi
        
        printf "${B}%-3s${N} ${Y}%-14s${N} %-12s %-11s ${C}%-5s${N} %s\n" \
            "$i" "$user" "$id" "$EXPIRE_DISPLAY" "$limit" "$STATUS_COLOR"
        i=$((i + 1))
    done
    
    echo ""
    echo -e "${Y}Total Akun:${N} $TOTAL"
    
    # Online users
    echo ""
    echo -e "${Y}User Online:${N}"
    if who | grep -q ppp; then
        who | grep ppp | while read line; do
            user=$(echo $line | awk '{print $1}')
            ip=$(echo $line | awk '{print $5}' | tr -d '()')
            echo -e "${G}$user${N} dari $ip"
        done
    else
        echo -e "${R}Tidak ada user online${N}"
    fi
    
    echo -e "${Y}══════════════════════════════════════════${N}"
    read -p "Tekan Enter untuk lanjut..."
}

view_account_detail() {
    echo -e "${Y}══════════════════════════════════════════${N}"
    echo -e "${B}LIHAT DETAIL AKUN${N}"
    echo -e "${Y}══════════════════════════════════════════${N}"
    
    list_accounts | head -20
    
    echo ""
    read -p "Masukkan username: " user
    if [ -z "$user" ]; then
        return
    fi
    
    # Check if user exists
    if ! jq -e ".clients[] | select(.username == \"$user\")" "$DB_FILE" > /dev/null; then
        echo -e "${R}User tidak ditemukan!${N}"
        read -p "Tekan Enter untuk lanjut..."
        return
    fi
    
    # Get client data
    CLIENT_DATA=$(jq -r ".clients[] | select(.username == \"$user\")" "$DB_FILE")
    
    USERNAME=$(echo "$CLIENT_DATA" | jq -r '.username')
    PASSWORD=$(echo "$CLIENT_DATA" | jq -r '.password')
    IPSEC_ID=$(echo "$CLIENT_DATA" | jq -r '.ipsec_id')
    IPSEC_PSK=$(echo "$CLIENT_DATA" | jq -r '.ipsec_psk')
    L2TP_SECRET=$(echo "$CLIENT_DATA" | jq -r '.l2tp_secret')
    NAME=$(echo "$CLIENT_DATA" | jq -r '.name')
    CREATED=$(echo "$CLIENT_DATA" | jq -r '.created')
    EXPIRE=$(echo "$CLIENT_DATA" | jq -r '.expire')
    LIMIT=$(echo "$CLIENT_DATA" | jq -r '.limit')
    STATUS=$(echo "$CLIENT_DATA" | jq -r '.status')
    
    SERVER_IP=$(jq -r '.server.ip' "$DB_FILE")
    
    echo -e "${G}============================================${N}"
    echo -e "${G}DETAIL AKUN: $NAME${N}"
    echo -e "${G}============================================${N}"
    echo ""
    echo -e "${Y}Informasi Akun:${N}"
    echo -e "Username: $USERNAME"
    echo -e "Status: $( [ "$STATUS" = "active" ] && echo -e "${G}$STATUS${N}" || echo -e "${R}$STATUS${N}" )"
    echo -e "Dibuat: $CREATED"
    echo -e "Expires: $EXPIRE"
    echo -e "IP Limit: $LIMIT"
    echo ""
    echo -e "${Y}Server:${N}"
    echo -e "IP: $SERVER_IP"
    echo -e "Port: UDP 500, 4500, 1701"
    echo ""
    echo -e "${Y}Credentials:${N}"
    echo -e "Password: ${G}$PASSWORD${N}"
    echo -e "L2TP Secret: ${G}$L2TP_SECRET${N}"
    echo -e "IPSec Identifier: ${G}$IPSEC_ID${N}"
    echo -e "IPSec PSK: ${G}$IPSEC_PSK${N}"
    echo ""
    echo -e "${Y}Cara Connect:${N}"
    echo -e "Server: $SERVER_IP"
    echo -e "Username: $USERNAME"
    echo -e "Password: $PASSWORD"
    echo -e "L2TP Secret: $L2TP_SECRET"
    echo -e "IPSec Identifier: $IPSEC_ID"
    echo -e "IPSec PSK: $IPSEC_PSK"
    echo -e "${G}============================================${N}"
    
    read -p "Tekan Enter untuk lanjut..."
}

delete_account() {
    echo -e "${Y}══════════════════════════════════════════${N}"
    echo -e "${B}HAPUS AKUN${N}"
    echo -e "${Y}══════════════════════════════════════════${N}"
    
    list_accounts | head -20
    
    echo ""
    echo -e "${G}[1]${N} Hapus by username"
    echo -e "${G}[2]${N} Hapus semua expired"
    echo -e "${R}[3]${N} Hapus SEMUA akun"
    echo -n -e "${B}Pilih [1-3]: ${N}"
    
    read choice
    case $choice in
        1)
            read -p "Masukkan username: " user
            if [ -z "$user" ]; then
                return
            fi
            
            # Check if exists
            if ! jq -e ".clients[] | select(.username == \"$user\")" "$DB_FILE" > /dev/null; then
                echo -e "${R}User tidak ditemukan!${N}"
                read -p "Tekan Enter untuk lanjut..."
                return
            fi
            
            # Get IPSec ID
            IPSEC_ID=$(jq -r ".clients[] | select(.username == \"$user\") | .ipsec_id" "$DB_FILE")
            
            # Remove from chap-secrets
            sed -i "/^$user /d" /etc/ppp/chap-secrets
            
            # Remove from ipsec.secrets
            sed -i "/^$IPSEC_ID /d" /etc/ipsec.secrets
            
            # Remove from database
            jq "del(.clients[] | select(.username == \"$user\"))" "$DB_FILE" > "$DB_FILE.tmp"
            mv "$DB_FILE.tmp" "$DB_FILE"
            
            # Remove config file
            rm -f "$CONFIG_DIR/clients/$user.conf"
            
            echo -e "${G}Akun $user berhasil dihapus!${N}"
            ;;
            
        2)
            echo -e "${Y}Menghapus semua akun expired...${N}"
            
            # Get expired clients
            EXPIRED=$(jq -r '.clients[] | select(.status == "expired") | .username' "$DB_FILE" 2>/dev/null)
            
            if [ -z "$EXPIRED" ]; then
                echo -e "${G}Tidak ada akun expired${N}"
            else
                COUNT=0
                echo "$EXPIRED" | while read user; do
                    # Get IPSec ID
                    IPSEC_ID=$(jq -r ".clients[] | select(.username == \"$user\") | .ipsec_id" "$DB_FILE")
                    
                    # Remove from chap-secrets
                    sed -i "/^$user /d" /etc/ppp/chap-secrets
                    
                    # Remove from ipsec.secrets
                    sed -i "/^$IPSEC_ID /d" /etc/ipsec.secrets
                    
                    # Remove config file
                    rm -f "$CONFIG_DIR/clients/$user.conf"
                    
                    COUNT=$((COUNT + 1))
                done
                
                # Remove from database
                jq '.clients = (.clients | map(select(.status != "expired")))' "$DB_FILE" > "$DB_FILE.tmp"
                mv "$DB_FILE.tmp" "$DB_FILE"
                
                echo -e "${G}Deleted $COUNT expired accounts${N}"
            fi
            ;;
            
        3)
            echo -e "${R}PERINGATAN: Ini akan menghapus SEMUA akun!${N}"
            read -p "Ketik 'YA' untuk konfirmasi: " confirm
            if [ "$confirm" != "YA" ]; then
                echo -e "${Y}Dibatalkan${N}"
                return
            fi
            
            # Backup
            TIMESTAMP=$(date +%Y%m%d_%H%M%S)
            cp /etc/ppp/chap-secrets /etc/ppp/chap-secrets.backup.$TIMESTAMP
            cp /etc/ipsec.secrets /etc/ipsec.secrets.backup.$TIMESTAMP
            
            # Clear chap-secrets
            echo "# Secrets for authentication using CHAP" > /etc/ppp/chap-secrets
            echo "# client server secret IP addresses" >> /etc/ppp/chap-secrets
            
            # Clear ipsec.secrets
            echo "# IPSec Pre-shared keys" > /etc/ipsec.secrets
            echo "# Format: IPSEC_ID %any : PSK \"PSK\"" >> /etc/ipsec.secrets
            
            # Clear database
            jq '.clients = []' "$DB_FILE" > "$DB_FILE.tmp"
            mv "$DB_FILE.tmp" "$DB_FILE"
            
            # Remove config files
            rm -f "$CONFIG_DIR/clients"/*.conf
            
            echo -e "${G}Semua akun telah dihapus!${N}"
            ;;
    esac
    
    read -p "Tekan Enter untuk lanjut..."
}

renew_account() {
    echo -e "${Y}══════════════════════════════════════════${N}"
    echo -e "${B}PERPANJANG AKUN${N}"
    echo -e "${Y}══════════════════════════════════════════${N}"
    
    list_accounts | head -20
    
    echo ""
    read -p "Masukkan username: " user
    if [ -z "$user" ]; then
        return
    fi
    
    # Check if exists
    if ! jq -e ".clients[] | select(.username == \"$user\")" "$DB_FILE" > /dev/null; then
        echo -e "${R}User tidak ditemukan!${N}"
        read -p "Tekan Enter untuk lanjut..."
        return
    fi
    
    # Get current expiry
    CURRENT=$(jq -r ".clients[] | select(.username == \"$user\") | .expire" "$DB_FILE")
    echo -e "Saat ini expire: ${Y}$CURRENT${N}"
    
    read -p "Tambahan hari (atau 'never'): " days
    
    if [ "$days" = "never" ]; then
        NEW_EXPIRE="never"
    else
        if ! [[ "$days" =~ ^[0-9]+$ ]]; then
            echo -e "${R}Hari harus angka!${N}"
            read -p "Tekan Enter untuk lanjut..."
            return
        fi
        
        TODAY=$(date +%Y-%m-%d)
        
        if [ "$CURRENT" = "never" ]; then
            NEW_EXPIRE="never"
        else
            # If expired, renew from today
            CURRENT_TS=$(date -d "$CURRENT" +%s 2>/dev/null || date -d "$TODAY" +%s)
            TODAY_TS=$(date -d "$TODAY" +%s)
            
            if [ $CURRENT_TS -lt $TODAY_TS ]; then
                NEW_EXPIRE=$(date -d "+$days days" +%Y-%m-%d)
            else
                NEW_EXPIRE=$(date -d "$CURRENT + $days days" +%Y-%m-%d)
            fi
        fi
    fi
    
    # Update database
    jq "(.clients[] | select(.username == \"$user\") | .expire) = \"$NEW_EXPIRE\"" \
        "$DB_FILE" > "$DB_FILE.tmp"
    mv "$DB_FILE.tmp" "$DB_FILE"
    
    jq "(.clients[] | select(.username == \"$user\") | .status) = \"active\"" \
        "$DB_FILE" > "$DB_FILE.tmp"
    mv "$DB_FILE.tmp" "$DB_FILE"
    
    echo -e "${G}Akun $user diperpanjang sampai $NEW_EXPIRE${N}"
    
    read -p "Tekan Enter untuk lanjut..."
}

manage_ip_limits() {
    echo -e "${Y}══════════════════════════════════════════${N}"
    echo -e "${B}ATUR LIMIT IP${N}"
    echo -e "${Y}══════════════════════════════════════════${N}"
    
    echo -e "${G}[1]${N} Set limit IP"
    echo -e "${G}[2]${N} Lihat semua limit"
    echo -e "${G}[3]${N} Reset limit"
    echo -e "${G}[4]${N} Monitor koneksi"
    echo -n -e "${B}Pilih [1-4]: ${N}"
    
    read choice
    case $choice in
        1)
            list_accounts | head -20
            echo ""
            read -p "Username: " user
            read -p "Limit IP baru: " limit
            
            if [ -z "$user" ] || [ -z "$limit" ]; then
                return
            fi
            
            if ! [[ "$limit" =~ ^[0-9]+$ ]]; then
                echo -e "${R}Limit harus angka!${N}"
                read -p "Tekan Enter untuk lanjut..."
                return
            fi
            
            if ! jq -e ".clients[] | select(.username == \"$user\")" "$DB_FILE" > /dev/null; then
                echo -e "${R}User tidak ditemukan!${N}"
                read -p "Tekan Enter untuk lanjut..."
                return
            fi
            
            jq "(.clients[] | select(.username == \"$user\") | .limit) = $limit" "$DB_FILE" > "$DB_FILE.tmp"
            mv "$DB_FILE.tmp" "$DB_FILE"
            
            echo -e "${G}Limit IP untuk $user diatur menjadi $limit${N}"
            ;;
            
        2)
            echo -e "${Y}Limit IP Semua Akun:${N}"
            echo ""
            
            jq -r '.clients[] | "\(.username) \(.limit)"' "$DB_FILE" 2>/dev/null | while read user limit; do
                # Count current connections
                COUNT=$(who | grep ppp | grep "^$user " | wc -l 2>/dev/null || echo 0)
                
                if [ "$COUNT" -gt "$limit" ]; then
                    echo -e "${R}$user: $COUNT/$limit (LEBIH)${N}"
                elif [ "$COUNT" -eq "$limit" ]; then
                    echo -e "${Y}$user: $COUNT/$limit (PENUH)${N}"
                else
                    echo -e "${G}$user: $COUNT/$limit${N}"
                fi
            done
            ;;
            
        3)
            list_accounts | head -20
            echo ""
            read -p "Username: " user
            
            if [ -z "$user" ]; then
                return
            fi
            
            if ! jq -e ".clients[] | select(.username == \"$user\")" "$DB_FILE" > /dev/null; then
                echo -e "${R}User tidak ditemukan!${N}"
                read -p "Tekan Enter untuk lanjut..."
                return
            fi
            
            jq "(.clients[] | select(.username == \"$user\") | .limit) = 2" "$DB_FILE" > "$DB_FILE.tmp"
            mv "$DB_FILE.tmp" "$DB_FILE"
            
            echo -e "${G}Limit IP $user direset ke default (2)${N}"
            ;;
            
        4)
            echo -e "${Y}Monitoring Koneksi:${N}"
            echo ""
            
            if ! which who > /dev/null; then
                apt install -y who
            fi
            
            TOTAL=0
            jq -r '.clients[] | "\(.username) \(.limit)"' "$DB_FILE" 2>/dev/null | while read user limit; do
                COUNT=$(who | grep ppp | grep "^$user " | wc -l 2>/dev/null || echo 0)
                
                if [ "$COUNT" -gt 0 ]; then
                    TOTAL=$((TOTAL + COUNT))
                    echo -e "${G}$user${N}: $COUNT koneksi (limit: $limit)"
                    
                    # Show IP addresses
                    who | grep "^$user " | awk '{print "  -> " $5}' | tr -d '()'
                fi
            done
            
            echo ""
            echo -e "${Y}Total koneksi aktif:${N} $TOTAL"
            ;;
    esac
    
    read -p "Tekan Enter untuk lanjut..."
}

view_online_users() {
    echo -e "${Y}══════════════════════════════════════════${N}"
    echo -e "${B}USER ONLINE${N}"
    echo -e "${Y}══════════════════════════════════════════${N}"
    
    if who | grep -q ppp; then
        echo -e "${G}Username       | IP Address       | Waktu${N}"
        echo -e "---------------|------------------|-----------------"
        
        who | grep ppp | while read line; do
            user=$(echo $line | awk '{print $1}')
            ip=$(echo $line | awk '{print $5}' | tr -d '()')
            time=$(echo $line | awk '{print $3, $4}')
            echo -e "${Y}$user${N}       | $ip       | $time"
        done
        
        TOTAL=$(who | grep ppp | wc -l)
        echo ""
        echo -e "${Y}Total online:${N} $TOTAL"
    else
        echo -e "${R}Tidak ada user online${N}"
    fi
    
    echo -e "${Y}══════════════════════════════════════════${N}"
    read -p "Tekan Enter untuk lanjut..."
}

server_status() {
    echo -e "${Y}══════════════════════════════════════════${N}"
    echo -e "${B}STATUS SERVER${N}"
    echo -e "${Y}══════════════════════════════════════════${N}"
    
    SERVER_IP=$(curl -s ifconfig.me)
    
    echo -e "${C}Informasi Server:${N}"
    echo -e "IP Address: $SERVER_IP"
    echo -e "Hostname: $(hostname)"
    echo -e "OS: $(lsb_release -ds)"
    echo -e "Uptime: $(uptime -p)"
    echo ""
    
    echo -e "${C}Status Services:${N}"
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
    
    echo -e "${C}Port Status:${N}"
    for port in 500 4500 1701; do
        if netstat -tuln 2>/dev/null | grep -q ":$port"; then
            echo -e "UDP $port: ${G}OPEN${N}"
        else
            echo -e "UDP $port: ${R}CLOSED${N}"
        fi
    done
    echo ""
    
    echo -e "${C}Statistik:${N}"
    TOTAL_CLIENTS=$(jq '.clients | length' "$DB_FILE" 2>/dev/null || echo "0")
    ONLINE_CLIENTS=$(who | grep ppp | wc -l 2>/dev/null || echo "0")
    echo -e "Total Akun: $TOTAL_CLIENTS"
    echo -e "Online Sekarang: $ONLINE_CLIENTS"
    
    echo -e "${Y}══════════════════════════════════════════${N}"
    read -p "Tekan Enter untuk lanjut..."
}

backup_restore() {
    echo -e "${Y}══════════════════════════════════════════${N}"
    echo -e "${B}BACKUP & RESTORE${N}"
    echo -e "${Y}══════════════════════════════════════════${N}"
    
    echo -e "${G}[1]${N} Buat backup"
    echo -e "${G}[2]${N} Restore backup"
    echo -e "${G}[3]${N} List backup"
    echo -n -e "${B}Pilih [1-3]: ${N}"
    
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
            
            echo -e "${G}Backup berhasil: $BACKUP_FILE${N}"
            ;;
        2)
            echo -e "${C}Backup yang tersedia:${N}"
            ls -lh "$CONFIG_DIR/backup/"*.tar.gz 2>/dev/null | nl
            
            read -p "Pilih nomor backup: " num
            BACKUP_FILE=$(ls "$CONFIG_DIR/backup/"*.tar.gz 2>/dev/null | sed -n "${num}p")
            
            if [ -f "$BACKUP_FILE" ]; then
                echo -e "${C}Restoring...${N}"
                tar -xzf "$BACKUP_FILE" -C /
                systemctl restart ipsec xl2tpd
                echo -e "${G}Restore selesai!${N}"
            else
                echo -e "${R}Pilihan tidak valid!${N}"
            fi
            ;;
        3)
            ls -lh "$CONFIG_DIR/backup/"*.tar.gz 2>/dev/null
            ;;
    esac
    
    read -p "Tekan Enter untuk lanjut..."
}

change_password() {
    echo -e "${Y}══════════════════════════════════════════${N}"
    echo -e "${B}GANTI PASSWORD${N}"
    echo -e "${Y}══════════════════════════════════════════${N}"
    
    list_accounts | head -20
    
    echo ""
    read -p "Masukkan username: " user
    if [ -z "$user" ]; then
        return
    fi
    
    # Check if user exists
    if ! jq -e ".clients[] | select(.username == \"$user\")" "$DB_FILE" > /dev/null; then
        echo -e "${R}User tidak ditemukan!${N}"
        read -p "Tekan Enter untuk lanjut..."
        return
    fi
    
    read -p "Password baru (kosong untuk auto): " new_pass
    
    if [ -z "$new_pass" ]; then
        new_pass=$(generate_string 12)
    fi
    
    # Update in chap-secrets
    sed -i "/^$user /d" /etc/ppp/chap-secrets
    echo "$user * $new_pass *" >> /etc/ppp/chap-secrets
    
    # Update in database
    jq "(.clients[] | select(.username == \"$user\") | .password) = \"$new_pass\"" \
        "$DB_FILE" > "$DB_FILE.tmp"
    mv "$DB_FILE.tmp" "$DB_FILE"
    
    echo -e "${G}Password untuk $user diubah menjadi: $new_pass${N}"
    
    read -p "Tekan Enter untuk lanjut..."
}

view_logs() {
    echo -e "${Y}══════════════════════════════════════════${N}"
    echo -e "${B}LIHAT LOGS${N}"
    echo -e "${Y}══════════════════════════════════════════${N}"
    
    echo -e "${G}[1]${N} Log IPSec"
    echo -e "${G}[2]${N} Log L2TP"
    echo -e "${G}[3]${N} Log Auth"
    echo -e "${G}[4]${N} Real-time monitoring"
    echo -n -e "${B}Pilih [1-4]: ${N}"
    
    read choice
    case $choice in
        1)
            journalctl -u ipsec --no-pager -n 30
            ;;
        2)
            journalctl -u xl2tpd --no-pager -n 30
            ;;
        3)
            tail -30 /var/log/auth.log | grep -E "(ppp|L2TP|IPSEC)"
            ;;
        4)
            echo -e "${Y}Monitoring real-time (Ctrl+C untuk berhenti)...${N}"
            tail -f /var/log/auth.log | grep -E "(ppp|L2TP|IPSEC)"
            ;;
    esac
    
    read -p "Tekan Enter untuk lanjut..."
}

restart_services() {
    echo -e "${Y}══════════════════════════════════════════${N}"
    echo -e "${B}RESTART SERVICES${N}"
    echo -e "${Y}══════════════════════════════════════════${N}"
    
    echo -e "${G}[1]${N} Restart semua services"
    echo -e "${G}[2]${N} Restart IPSec saja"
    echo -e "${G}[3]${N} Restart L2TP saja"
    echo -e "${G}[4]${N} Stop semua services"
    echo -e "${G}[5]${N} Start semua services"
    echo -n -e "${B}Pilih [1-5]: ${N}"
    
    read choice
    case $choice in
        1)
            systemctl restart ipsec xl2tpd
            echo -e "${G}Semua services di-restart${N}"
            ;;
        2)
            systemctl restart ipsec
            echo -e "${G}IPSec di-restart${N}"
            ;;
        3)
            systemctl restart xl2tpd
            echo -e "${G}L2TP di-restart${N}"
            ;;
        4)
            systemctl stop ipsec xl2tpd
            echo -e "${Y}Semua services di-stop${N}"
            ;;
        5)
            systemctl start ipsec xl2tpd
            echo -e "${G}Semua services di-start${N}"
            ;;
    esac
    
    echo ""
    echo -e "${Y}Status saat ini:${N}"
    systemctl status ipsec --no-pager -l | head -5
    systemctl status xl2tpd --no-pager -l | head -5
    
    read -p "Tekan Enter untuk lanjut..."
}

test_connection() {
    echo -e "${Y}══════════════════════════════════════════${N}"
    echo -e "${B}TEST KONEKSI${N}"
    echo -e "${Y}══════════════════════════════════════════${N}"
    
    echo -e "${G}[1]${N} Test port server"
    echo -e "${G}[2]${N} Test service status"
    echo -e "${G}[3]${N} Test DNS resolution"
    echo -e "${G}[4]${N} Test IP forwarding"
    echo -n -e "${B}Pilih [1-4]: ${N}"
    
    read choice
    case $choice in
        1)
            echo -e "${Y}Testing server ports...${N}"
            SERVER_IP=$(jq -r '.server.ip' "$DB_FILE")
            
            for port in 500 4500 1701; do
                if timeout 2 nc -z -u $SERVER_IP $port 2>/dev/null; then
                    echo -e "UDP $port: ${G}OPEN${N}"
                else
                    echo -e "UDP $port: ${R}CLOSED${N}"
                fi
            done
            ;;
        2)
            echo -e "${Y}Testing service status...${N}"
            
            if systemctl is-active --quiet ipsec; then
                echo -e "IPSec: ${G}ACTIVE${N}"
            else
                echo -e "IPSec: ${R}INACTIVE${N}"
                journalctl -u ipsec --no-pager -n 3
            fi
            
            if systemctl is-active --quiet xl2tpd; then
                echo -e "L2TP: ${G}ACTIVE${N}"
            else
                echo -e "L2TP: ${R}INACTIVE${N}"
                journalctl -u xl2tpd --no-pager -n 3
            fi
            ;;
        3)
            echo -e "${Y}Testing DNS...${N}"
            nslookup google.com 8.8.8.8 2>/dev/null | head -5
            ;;
        4)
            echo -e "${Y}Testing IP forwarding...${N}"
            if [ $(cat /proc/sys/net/ipv4/ip_forward) -eq 1 ]; then
                echo -e "IP Forwarding: ${G}ENABLED${N}"
            else
                echo -e "IP Forwarding: ${R}DISABLED${N}"
            fi
            ;;
    esac
    
    read -p "Tekan Enter untuk lanjut..."
}

# Main loop
while true; do
    show_menu
    read choice
    
    case $choice in
        1) create_auto_account ;;
        2) create_custom_account ;;
        3) list_accounts ;;
        4) view_account_detail ;;
        5) delete_account ;;
        6) renew_account ;;
        7) manage_ip_limits ;;
        8) view_online_users ;;
        9) server_status ;;
        10) backup_restore ;;
        11) change_password ;;
        12) view_logs ;;
        13) restart_services ;;
        14) test_connection ;;
        0)
            echo -e "${G}Terima kasih!${N}"
            exit 0
            ;;
        *)
            echo -e "${R}Pilihan salah!${N}"
            sleep 1
            ;;
    esac
done
EOF
    chmod +x /usr/local/bin/l2tp
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
    
    echo -e "${G}==========================================${N}"
    echo -e "${G}INSTALASI BERHASIL!${N}"
    echo -e "${G}==========================================${N}"
    echo ""
    
    echo -e "${Y}INFORMASI SERVER:${N}"
    echo -e "IP Address: $SERVER_IP"
    echo -e "Ports: UDP 500, 4500, 1701"
    echo ""
    
    echo -e "${Y}CARA MENGGUNAKAN:${N}"
    echo -e "1. Buka menu utama: ${G}l2tp${N}"
    echo -e "2. Pilih 1 untuk buat akun auto"
    echo -e "3. Atau pilih 2 untuk buat akun custom"
    echo ""
    
    echo -e "${Y}CONTOH BUAT AKUN:${N}"
    echo -e "1. Ketik: ${G}l2tp${N}"
    echo -e "2. Pilih 1 (Buat Akun Auto)"
    echo -e "3. Masukkan masa aktif dan limit IP"
    echo -e "4. Semua credential akan auto generate"
    echo ""
    
    echo -e "${Y}FITUR UTAMA:${N}"
    echo -e "• Buat akun dengan semua field auto"
    echo -e "• Username & Password untuk login"
    echo -e "• L2TP Secret untuk L2TP"
    echo -e "• IPSec Identifier & PSK untuk IPSec"
    echo -e "• Batas masa aktif dan limit IP"
    echo -e "• Management lengkap dari menu"
    echo ""
    
    echo -e "${R}PENTING:${N}"
    echo -e "1. Buka port di firewall: UDP 500, 4500, 1701"
    echo -e "2. Test koneksi setelah setup"
    echo -e "3. Backup konfigurasi secara rutin"
    echo -e "${G}==========================================${N}"
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
    create_main_menu
    start_services
    show_completion
}

# Run
if [ "$1" = "uninstall" ]; then
    echo -e "${R}Uninstalling...${N}"
    systemctl stop ipsec xl2tpd
    apt remove -y strongswan xl2tpd
    rm -f /usr/local/bin/l2tp
    rm -rf /etc/l2tp-vpn
    echo -e "${G}Uninstall complete!${N}"
else
    main
fi

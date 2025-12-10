Cara Install:
bash

# Login sebagai root
sudo -i

# One-line install
bash <(curl -s https://raw.githubusercontent.com/sukronwae85-design/l2tponly/main/install-l2tp.sh)

# Atau download
wget https://raw.githubusercontent.com/sukronwae85-design/l2tponly/main/install-l2tp.sh
chmod +x install-l2tp.sh
./install-l2tp.sh

Cara Kerja Sistem:

Field yang diberikan saat buat akun:
text

========================================
SERVER INFORMATION:
IP Address: 103.215.xxx.xxx    # Alamat Server
L2TP Secret: AbC123xYz456      # Rahasia L2TP (SAMA untuk semua client)

CLIENT INFORMATION:
IPSec Identifier: CLIENT1234    # Pengenal IPSec (sebagai username)
IPSec PSK: XyZ789DeF012GhI345   # Kunci Pra-bagi IPSec (sebagai password)
Expires: 2024-02-20
IP Limit: 2
========================================

Cara Connect di Client:

Setting VPN:
text

Type: L2TP/IPSec PSK
Server: 103.215.xxx.xxx          # Alamat Server
L2TP Secret: AbC123xYz456        # Rahasia L2TP
IPSec Identifier: CLIENT1234      # Pengenal IPSec (username)
IPSec PSK: XyZ789DeF012GhI345     # Kunci Pra-bagi (password)
Username: [kosongkan]
Password: [kosongkan]

Management Commands:
bash

# Menu utama
l2tp-menu

# Buat client baru (auto semua)
l2tp-add --auto --days 30 --limit 2

# Buat client custom
l2tp-add --id MYID --psk MYPASSWORD --days 30 --limit 3 --name "Client Saya"

# Lihat semua client
l2tp-list

# Hapus client
l2tp-del CLIENT1234

# Atur limit IP
l2tp-limit set CLIENT1234 3

# Perpanjang client
l2tp-renew CLIENT1234 30

Fitur Lengkap:

✅ L2TP Secret auto generate (sama untuk semua client)
✅ IPSec Identifier custom/auto (sebagai username)
✅ IPSec PSK custom/auto (sebagai password)
✅ Batas masa aktif (auto expire)
✅ Batas IP login (max connections)
✅ Menu management lengkap (l2tp-menu)
✅ Auto clean expired clients
✅ Backup & restore
✅ Change L2TP Secret (global untuk semua)
✅ Bulk create clients
✅ Monitoring & logs

Sistem ini sudah benar! Setiap client dapat:

    L2TP Secret yang sama (global)

    IPSec Identifier unik (username mereka)

    IPSec PSK unik (password mereka)

Semua modul yang diminta sudah ada! 🎯
This response is AI-generated, for reference only.
f

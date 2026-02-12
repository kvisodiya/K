#!/bin/bash
# Army-grade Debian 11 Hardening Installer (Editable Version)

set -e

# 1️⃣ Update system and install essentials
apt update && apt upgrade -y
apt install git sudo -y

# 2️⃣ Clone OVH Debian-CIS repo
cd /root
if [ ! -d "debian-cis" ]; then
    git clone https://github.com/ovh/debian-cis.git
fi
cd debian-cis

# 3️⃣ Fix paths in /etc/default/cis-hardening
CONFIG="/etc/default/cis-hardening"
sudo touch $CONFIG
sudo bash -c "cat > $CONFIG <<EOF
CIS_LIB_DIR='$(pwd)/lib'
CIS_CHECKS_DIR='$(pwd)/bin/hardening'
CIS_CONF_DIR='$(pwd)/etc'
CIS_TMP_DIR='$(pwd)/tmp'
CIS_VERSIONS_DIR='$(pwd)/versions'
EOF"

# 4️⃣ Make all scripts executable
chmod -R +x bin/hardening

# 5️⃣ Set Level 5 hardening
sudo bin/hardening.sh --set-hardening-level 5

# 6️⃣ Allow SSH so you don't get locked out
sudo bin/hardening.sh --allow-service ssh

# 7️⃣ Apply all hardening scripts automatically
sudo bin/hardening.sh --apply

# 8️⃣ Give full permissions to the user for editing everything
sudo chown -R $USER:$USER /root/debian-cis
sudo chmod -R 775 /root/debian-cis

echo "✅ Hardening applied! All files are now editable in /root/debian-cis"
echo "Run 'sudo lynis audit system --quiet' to check score."

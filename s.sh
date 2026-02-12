#!/bin/bash
##############################################################################
# CIS Level 5 Hardening - Simple One-Script Setup
# For fresh Debian/Ubuntu VPS over SSH
# Usage: chmod +x start.sh && sudo ./start.sh
##############################################################################

set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0"; exit 1; fi

SSH_PORT="${SSH_PORT:-22}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "==========================================="
echo "  CIS Level 5 Hardening - Starting..."
echo "  SSH Port: ${SSH_PORT}"
echo "==========================================="

# ── Backup ──
echo "[*] Backing up configs..."
mkdir -p /root/backup_${TIMESTAMP}
cp -a /etc/ssh/sshd_config /root/backup_${TIMESTAMP}/ 2>/dev/null || true
cp -a /etc/sysctl.conf /root/backup_${TIMESTAMP}/ 2>/dev/null || true
cp -a /etc/login.defs /root/backup_${TIMESTAMP}/ 2>/dev/null || true
cp -a /etc/pam.d/ /root/backup_${TIMESTAMP}/ 2>/dev/null || true

# ── Install packages ──
echo "[*] Installing packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
  git curl wget sudo vim openssh-server \
  fail2ban ufw auditd aide aide-common \
  libpam-pwquality apparmor apparmor-utils \
  chrony unattended-upgrades rsyslog cron \
  iptables-persistent rkhunter debsums \
  net-tools acl apt-show-versions jq bc

# ── SSH Hardening ──
echo "[*] Hardening SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

cat > /etc/ssh/sshd_config <<EOF
Port ${SSH_PORT}
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 4
MaxSessions 10
ClientAliveInterval 300
ClientAliveCountMax 3
LoginGraceTime 60
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
IgnoreRhosts yes
HostbasedAuthentication no
Banner /etc/issue.net
LogLevel VERBOSE
UsePAM yes
StrictModes yes
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

echo "Unauthorized access prohibited. All activity monitored." > /etc/issue.net
chmod 600 /etc/ssh/sshd_config
sshd -t && systemctl restart sshd || cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config

# ── Firewall ──
echo "[*] Setting up firewall..."
ufw --force reset >/dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw allow ${SSH_PORT}/tcp
ufw --force enable

# ── Fail2ban ──
echo "[*] Setting up fail2ban..."
cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = ${SSH_PORT}
maxretry = 3
bantime = 7200
findtime = 600
EOF
systemctl enable fail2ban && systemctl restart fail2ban

# ── Kernel hardening ──
echo "[*] Hardening kernel..."
cat > /etc/sysctl.d/99-cis.conf <<EOF
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
EOF
sysctl --system >/dev/null 2>&1

# ── Disable junk modules ──
echo "[*] Disabling unused modules..."
for mod in cramfs freevxfs jffs2 hfs hfsplus squashfs udf dccp sctp rds tipc usb-storage; do
  echo "install ${mod} /bin/true" > /etc/modprobe.d/${mod}.conf
done

# ── Password policy ──
echo "[*] Setting password policy..."
cat > /etc/security/pwquality.conf <<EOF
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
EOF

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs

# ── File permissions ──
echo "[*] Fixing permissions..."
chmod 644 /etc/passwd /etc/group
chmod 640 /etc/shadow /etc/gshadow
chmod 600 /etc/ssh/sshd_config
chmod 600 /etc/crontab
for d in /etc/cron.{hourly,daily,weekly,monthly,d}; do
  [ -d "$d" ] && chmod 700 "$d"
done
echo "root" > /etc/cron.allow && chmod 600 /etc/cron.allow
[ -f /boot/grub/grub.cfg ] && chmod 400 /boot/grub/grub.cfg

# ── Audit rules ──
echo "[*] Configuring audit..."
systemctl enable auditd && systemctl start auditd
cat > /etc/audit/rules.d/cis.rules <<'EOF'
-D
-b 8192
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd
-w /var/log/sudo.log -p wa -k actions
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S unlink -S rename -F auid>=1000 -F auid!=4294967295 -k delete
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-e 2
EOF
augenrules --load 2>/dev/null || true

# ── Disable junk services ──
echo "[*] Disabling unnecessary services..."
for svc in avahi-daemon cups rpcbind nfs-server vsftpd dovecot smbd squid snmpd; do
  systemctl disable ${svc} 2>/dev/null; systemctl mask ${svc} 2>/dev/null
done
apt-get purge -y -qq telnet rsh-client nis talk 2>/dev/null || true

# ── AppArmor ──
echo "[*] Enabling AppArmor..."
systemctl enable apparmor && systemctl start apparmor

# ── Auto updates ──
echo "[*] Enabling auto security updates..."
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# ── AIDE ──
echo "[*] Initializing AIDE (background)..."
aideinit --yes --force &>/dev/null &

# ── Clone and run OVH debian-cis ──
echo "[*] Cloning OVH debian-cis..."
rm -rf /opt/debian-cis
git clone --depth 1 https://github.com/ovh/debian-cis.git /opt/debian-cis
cd /opt/debian-cis

cp debian/default /etc/default/cis-hardening
sed -i "s|CIS_LIB_DIR=.*|CIS_LIB_DIR='/opt/debian-cis/lib'|" /etc/default/cis-hardening
sed -i "s|CIS_CHECKS_DIR=.*|CIS_CHECKS_DIR='/opt/debian-cis/bin/hardening'|" /etc/default/cis-hardening
sed -i "s|CIS_CONF_DIR=.*|CIS_CONF_DIR='/opt/debian-cis/etc'|" /etc/default/cis-hardening

echo "[*] Setting Level 5..."
chmod +x bin/hardening.sh
bash bin/hardening.sh --set-hardening-level 5 || true

# Skip partition checks (VPS doesn't have separate partitions)
for f in etc/conf.d/1.1.{2,3,4,5,6,7,8,9,10,11,12,13,14}*; do
  [ -f "$f" ] && sed -i 's/status=.*/status=disabled/' "$f"
done

echo "[*] Running audit..."
bash bin/hardening.sh --audit-all 2>&1 | tee /var/log/cis-audit.txt

echo "[*] Applying fixes..."
bash bin/hardening.sh --apply 2>&1 | tee /var/log/cis-apply.txt || true

# ── Make sure SSH survived ──
sshd -t 2>/dev/null || cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
systemctl restart sshd

echo ""
echo "==========================================="
echo "  DONE! CIS Level 5 Hardening Complete"
echo "==========================================="
echo "  SSH: port ${SSH_PORT} (running)"
echo "  Logs: /var/log/cis-audit.txt"
echo "        /var/log/cis-apply.txt"
echo "  Backup: /root/backup_${TIMESTAMP}/"
echo ""
echo "  >>> REBOOT NOW: sudo reboot <<<"
echo "==========================================="

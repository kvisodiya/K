#!/bin/bash
##############################################################################
# CIS Level 5 - Simple Setup for Fresh Debian/Ubuntu VPS
# Usage: chmod +x start.sh && sudo bash start.sh
##############################################################################

# Dont exit on errors - handle them
set +e

# Must be root
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Run as root -> sudo bash start.sh"
  exit 1
fi

SSH_PORT="${SSH_PORT:-22}"
BACKUP="/root/backup_$(date +%s)"

echo ""
echo "=============================="
echo " CIS Level 5 - Starting"
echo " SSH Port: ${SSH_PORT}"
echo "=============================="
echo ""

########################################
# STEP 1: Backup
########################################
echo "[1/10] Backing up..."
mkdir -p ${BACKUP}
cp /etc/ssh/sshd_config ${BACKUP}/ 2>/dev/null
cp /etc/login.defs ${BACKUP}/ 2>/dev/null
cp /etc/sysctl.conf ${BACKUP}/ 2>/dev/null
cp -r /etc/pam.d ${BACKUP}/ 2>/dev/null
echo "  Backup -> ${BACKUP}"

########################################
# STEP 2: Fix dpkg + Install packages
########################################
echo "[2/10] Installing packages..."
export DEBIAN_FRONTEND=noninteractive

# Fix broken state
dpkg --configure -a 2>/dev/null

apt-get update -y

# Install in small groups so one failure doesnt kill everything
apt-get install -y git curl wget sudo vim nano openssh-server 2>/dev/null
apt-get install -y net-tools iproute2 procps jq bc htop tmux 2>/dev/null
apt-get install -y fail2ban ufw 2>/dev/null
apt-get install -y auditd 2>/dev/null
apt-get install -y libpam-pwquality 2>/dev/null
apt-get install -y apparmor apparmor-utils 2>/dev/null
apt-get install -y unattended-upgrades 2>/dev/null
apt-get install -y rsyslog cron 2>/dev/null
apt-get install -y chrony 2>/dev/null
apt-get install -y aide 2>/dev/null
apt-get install -y rkhunter debsums acl 2>/dev/null
apt-get install -y iptables 2>/dev/null
apt-get install -y lsb-release ca-certificates gnupg2 2>/dev/null

echo "  Packages done"

########################################
# STEP 3: Make sure SSH works first
########################################
echo "[3/10] Securing SSH..."
systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null

# Save working config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.WORKING

cat > /etc/ssh/sshd_config <<EOF
Port ${SSH_PORT}
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
PrintMotd no
PrintLastLog yes
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

echo "Unauthorized access prohibited." > /etc/issue.net

# Test before restarting
if sshd -t 2>/dev/null; then
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
  echo "  SSH OK on port ${SSH_PORT}"
else
  echo "  SSH config error - reverting"
  cp /etc/ssh/sshd_config.WORKING /etc/ssh/sshd_config
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
fi

########################################
# STEP 4: Firewall
########################################
echo "[4/10] Firewall..."
if command -v ufw >/dev/null 2>&1; then
  ufw --force reset >/dev/null 2>&1
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow ${SSH_PORT}/tcp
  ufw --force enable
  echo "  UFW active"
else
  echo "  UFW not found - skipping"
fi

########################################
# STEP 5: Fail2ban
########################################
echo "[5/10] Fail2ban..."
if command -v fail2ban-client >/dev/null 2>&1; then
  mkdir -p /etc/fail2ban
  cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 7200
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ${SSH_PORT}
maxretry = 3
EOF
  systemctl enable fail2ban 2>/dev/null
  systemctl restart fail2ban 2>/dev/null
  echo "  Fail2ban active"
else
  echo "  Fail2ban not found - skipping"
fi

########################################
# STEP 6: Kernel hardening
########################################
echo "[6/10] Kernel hardening..."
cat > /etc/sysctl.d/99-cis.conf <<EOF
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.suid_dumpable = 0
EOF
sysctl --system >/dev/null 2>&1
echo "  Sysctl applied"

# Disable junk modules
for mod in cramfs freevxfs jffs2 hfs hfsplus squashfs udf dccp sctp rds tipc usb-storage; do
  echo "install ${mod} /bin/true" > /etc/modprobe.d/disable-${mod}.conf 2>/dev/null
  modprobe -r ${mod} 2>/dev/null
done
echo "  Modules disabled"

########################################
# STEP 7: Password + Permissions
########################################
echo "[7/10] Passwords & permissions..."

# Password quality
if [ -f /etc/security/pwquality.conf ]; then
  cat > /etc/security/pwquality.conf <<EOF
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
EOF
fi

# Login defs
if [ -f /etc/login.defs ]; then
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
  sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
  sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
  sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
fi

# File permissions
chmod 644 /etc/passwd /etc/group 2>/dev/null
chmod 640 /etc/shadow 2>/dev/null
chmod 640 /etc/gshadow 2>/dev/null
chmod 600 /etc/crontab 2>/dev/null
chmod 600 /etc/ssh/sshd_config 2>/dev/null
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
  [ -d "$d" ] && chmod 700 "$d" 2>/dev/null
done
[ -f /boot/grub/grub.cfg ] && chmod 400 /boot/grub/grub.cfg 2>/dev/null

echo "root" > /etc/cron.allow 2>/dev/null
chmod 600 /etc/cron.allow 2>/dev/null

echo "  Done"

########################################
# STEP 8: Audit
########################################
echo "[8/10] Audit system..."
if command -v auditctl >/dev/null 2>&1; then
  systemctl enable auditd 2>/dev/null
  systemctl start auditd 2>/dev/null

  cat > /etc/audit/rules.d/cis.rules <<'EOF'
-D
-b 8192
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S unlink -S rename -F auid>=1000 -F auid!=4294967295 -k delete
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-e 2
EOF

  augenrules --load 2>/dev/null
  systemctl restart auditd 2>/dev/null
  echo "  Auditd active"
else
  echo "  Auditd not found - skipping"
fi

########################################
# STEP 9: Disable junk + enable good stuff
########################################
echo "[9/10] Services cleanup..."

# Disable
for svc in avahi-daemon cups rpcbind nfs-server vsftpd dovecot smbd squid snmpd; do
  systemctl disable ${svc} 2>/dev/null
  systemctl stop ${svc} 2>/dev/null
done

# Remove junk
apt-get purge -y telnet rsh-client nis talk 2>/dev/null
apt-get autoremove -y 2>/dev/null

# Enable good stuff
systemctl enable apparmor 2>/dev/null && systemctl start apparmor 2>/dev/null
systemctl enable chrony 2>/dev/null && systemctl start chrony 2>/dev/null
systemctl enable rsyslog 2>/dev/null && systemctl start rsyslog 2>/dev/null
systemctl enable cron 2>/dev/null && systemctl start cron 2>/dev/null

# Auto updates
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

echo "  Done"

########################################
# STEP 10: OVH debian-cis
########################################
echo "[10/10] OVH debian-cis benchmark..."

rm -rf /opt/debian-cis
git clone --depth 1 https://github.com/ovh/debian-cis.git /opt/debian-cis

if [ -d /opt/debian-cis ]; then
  cd /opt/debian-cis

  # Setup paths
  cp debian/default /etc/default/cis-hardening
  sed -i "s#CIS_LIB_DIR=.*#CIS_LIB_DIR='/opt/debian-cis/lib'#" /etc/default/cis-hardening
  sed -i "s#CIS_CHECKS_DIR=.*#CIS_CHECKS_DIR='/opt/debian-cis/bin/hardening'#" /etc/default/cis-hardening
  sed -i "s#CIS_CONF_DIR=.*#CIS_CONF_DIR='/opt/debian-cis/etc'#" /etc/default/cis-hardening
  sed -i "s#CIS_ROOT_DIR=.*#CIS_ROOT_DIR='/opt/debian-cis'#" /etc/default/cis-hardening

  chmod +x bin/hardening.sh

  # Set level 5
  echo "  Setting level 5..."
  bash bin/hardening.sh --set-hardening-level 5 2>&1 | tail -3

  # Disable partition checks (VPS = single partition)
  echo "  Disabling partition checks for VPS..."
  if [ -d etc/conf.d ]; then
    for num in 1.1.2 1.1.3 1.1.4 1.1.5 1.1.6 1.1.7 1.1.8 1.1.9 1.1.10 1.1.11 1.1.12 1.1.13 1.1.14 1.1.15 1.1.16 1.1.17; do
      for f in etc/conf.d/${num}*.cfg; do
        [ -f "$f" ] && sed -i 's/status=.*/status=disabled/' "$f"
      done
    done
  fi

  # Run audit
  echo "  Running audit..."
  bash bin/hardening.sh --audit-all 2>&1 | tee /var/log/cis-audit.log | tail -20

  # Apply fixes
  echo "  Applying fixes..."
  bash bin/hardening.sh --apply 2>&1 | tee /var/log/cis-apply.log | tail -20

  echo "  debian-cis done"
else
  echo "  ERROR: git clone failed"
fi

########################################
# FINAL: Make sure SSH still works
########################################
echo ""
echo "[*] Final SSH check..."
if sshd -t 2>/dev/null; then
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
  echo "  SSH OK"
else
  echo "  SSH broken - restoring backup"
  cp ${BACKUP}/sshd_config /etc/ssh/sshd_config
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
fi

# Quick status
echo ""
echo "=============================="
echo " DONE!"
echo "=============================="
echo ""
echo " SSH:       $(systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null) (port ${SSH_PORT})"
echo " Firewall:  $(ufw status 2>/dev/null | head -1)"
echo " Fail2ban:  $(systemctl is-active fail2ban 2>/dev/null)"
echo " Auditd:    $(systemctl is-active auditd 2>/dev/null)"
echo " AppArmor:  $(systemctl is-active apparmor 2>/dev/null)"
echo ""
echo " Logs:   /var/log/cis-audit.log"
echo "         /var/log/cis-apply.log"
echo " Backup: ${BACKUP}/"
echo ""
echo " >>> Run: sudo reboot <<<"
echo "=============================="

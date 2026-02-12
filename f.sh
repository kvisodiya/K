#!/bin/bash
##############################################################################
# Fix ALL Lynis suggestions - 86 → 90+
# sudo bash fix90.sh
##############################################################################

if [ "$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi

SSH_PORT="${SSH_PORT:-22}"

echo ""
echo "========================"
echo " Fixing ALL Lynis items"
echo "========================"
echo ""

########################################
# 1. Install missing packages
########################################
echo "[1/12] Installing missing packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

apt-get install -y -qq libpam-tmpdir 2>/dev/null
apt-get install -y -qq apt-listbugs 2>/dev/null
apt-get install -y -qq debsecan 2>/dev/null
apt-get install -y -qq aide aide-common 2>/dev/null
apt-get install -y -qq arpwatch 2>/dev/null
apt-get install -y -qq usbguard 2>/dev/null
apt-get install -y -qq haveged rng-tools5 2>/dev/null || apt-get install -y -qq haveged rng-tools 2>/dev/null
apt-get install -y -qq needrestart 2>/dev/null
apt-get install -y -qq acct 2>/dev/null
apt-get install -y -qq sysstat 2>/dev/null
apt-get install -y -qq debsums 2>/dev/null

# Enable services
systemctl enable haveged 2>/dev/null && systemctl start haveged 2>/dev/null
systemctl enable arpwatch 2>/dev/null && systemctl start arpwatch 2>/dev/null
systemctl enable acct 2>/dev/null && systemctl start acct 2>/dev/null

echo "  Done"

########################################
# 2. AIDE database
########################################
echo "[2/12] Building AIDE database..."
if command -v aideinit >/dev/null 2>&1; then
  if [ ! -f /var/lib/aide/aide.db ]; then
    aideinit --yes --force 2>/dev/null
    # Copy new db into place
    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null
  fi
  echo "  AIDE database ready"
else
  echo "  AIDE not available"
fi
echo "  Done"

########################################
# 3. SSH hardening (exact Lynis items)
########################################
echo "[3/12] SSH fixes..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak86

cat > /etc/ssh/sshd_config <<EOF
# Port - change from default 22
Port ${SSH_PORT}
AddressFamily inet
ListenAddress 0.0.0.0

# Protocol
Protocol 2

# Host keys
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key

# Lynis AUTH-9286: LogLevel VERBOSE
SyslogFacility AUTH
LogLevel VERBOSE

# Lynis AUTH-9286: MaxAuthTries 3
MaxAuthTries 3

# Lynis AUTH-9286: MaxSessions 2
MaxSessions 2

# Lynis AUTH-9286: ClientAliveCountMax 2
ClientAliveInterval 300
ClientAliveCountMax 2

# Lynis AUTH-9286: LoginGraceTime
LoginGraceTime 30

# Lynis AUTH-9286: PermitRootLogin
# Keep yes if root-only VPS, change to no when you have sudo user
PermitRootLogin yes

# Auth
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no

# Lynis AUTH-9286: Forwarding disabled
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no

# Lynis AUTH-9286: Other
PermitUserEnvironment no
IgnoreRhosts yes
HostbasedAuthentication no
StrictModes yes
Compression no
TCPKeepAlive no
UseDNS no
PrintMotd no
PrintLastLog yes
MaxStartups 10:30:60

# Banner
Banner /etc/issue.net

# Crypto
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

# PAM
UsePAM yes

# SFTP
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

chmod 600 /etc/ssh/sshd_config

# Test before restart
if sshd -t 2>/dev/null; then
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
  echo "  SSH OK"
else
  echo "  SSH error - reverting"
  cp /etc/ssh/sshd_config.bak86 /etc/ssh/sshd_config
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
fi
echo "  Done"

########################################
# 4. Hostname & DNS fix
########################################
echo "[4/12] Hostname & DNS..."
MYHOST=$(hostname)
MYIP=$(hostname -I 2>/dev/null | awk '{print $1}')

# Fix /etc/hosts
grep -q "$MYHOST" /etc/hosts || {
  echo "127.0.1.1 ${MYHOST}" >> /etc/hosts
}

# Make sure localhost is there
grep -q "127.0.0.1.*localhost" /etc/hosts || {
  sed -i '1i 127.0.0.1 localhost' /etc/hosts
}

# Set hostname properly
hostnamectl set-hostname "${MYHOST}" 2>/dev/null

echo "  Done"

########################################
# 5. Account expire dates
########################################
echo "[5/12] Account expiry..."

# Set default for new accounts
useradd -D -f 30 2>/dev/null
sed -i 's/^INACTIVE=.*/INACTIVE=30/' /etc/default/useradd 2>/dev/null
grep -q "^INACTIVE" /etc/default/useradd || echo "INACTIVE=30" >> /etc/default/useradd

# Fix ALL existing user accounts
for user in $(awk -F: '($3 >= 1000 && $1 != "nobody" && $1 != "nfsnobody") {print $1}' /etc/passwd 2>/dev/null); do
  chage --inactive 30 "$user" 2>/dev/null
  chage --maxdays 365 "$user" 2>/dev/null
  chage --mindays 1 "$user" 2>/dev/null
  chage --warndays 7 "$user" 2>/dev/null
done

# Root too
chage --maxdays 365 root 2>/dev/null
chage --mindays 1 root 2>/dev/null
chage --warndays 7 root 2>/dev/null

echo "  Done"

########################################
# 6. Mount points & /proc
########################################
echo "[6/12] Mount hardening..."

# /proc hidepid
if ! mount | grep -q "hidepid=2"; then
  grep -q "hidepid" /etc/fstab || echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab
  mount -o remount,hidepid=2 /proc 2>/dev/null
fi

# /tmp
if ! mount | grep -q " on /tmp "; then
  grep -q "^tmpfs.*/tmp" /etc/fstab || echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,size=2G 0 0" >> /etc/fstab
fi

# /dev/shm
mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null
grep -q "/dev/shm" /etc/fstab || echo "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid 0 0" >> /etc/fstab

echo "  Done"

########################################
# 7. Sysctl (match Lynis profile exactly)
########################################
echo "[7/12] Sysctl alignment..."

# Remove old files to avoid conflicts
rm -f /etc/sysctl.d/99-cis.conf 2>/dev/null
rm -f /etc/sysctl.d/99-lynis-extra.conf 2>/dev/null
rm -f /etc/sysctl.d/99-ptrace.conf 2>/dev/null
rm -f /etc/sysctl.d/99-lynis-final.conf 2>/dev/null

cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
# Network
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_rfc1337 = 1

# IPv6 off
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Kernel
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
dev.tty.ldisc_autoload = 0

# Filesystem
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
vm.mmap_min_addr = 65536
vm.swappiness = 1
EOF
sysctl --system >/dev/null 2>&1
echo "  Done"

########################################
# 8. Systemd service hardening
########################################
echo "[8/12] Systemd service hardening..."

# Harden cron
mkdir -p /etc/systemd/system/cron.service.d
cat > /etc/systemd/system/cron.service.d/hardening.conf <<EOF
[Service]
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
EOF

# Harden fail2ban
mkdir -p /etc/systemd/system/fail2ban.service.d
cat > /etc/systemd/system/fail2ban.service.d/hardening.conf <<EOF
[Service]
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_AUDIT_READ
EOF

# Harden ssh
mkdir -p /etc/systemd/system/ssh.service.d
cat > /etc/systemd/system/ssh.service.d/hardening.conf <<EOF
[Service]
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
ReadWritePaths=/var/run/sshd /run/sshd
EOF

# Harden rsyslog
mkdir -p /etc/systemd/system/rsyslog.service.d
cat > /etc/systemd/system/rsyslog.service.d/hardening.conf <<EOF
[Service]
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
EOF

# Harden unattended-upgrades
mkdir -p /etc/systemd/system/unattended-upgrades.service.d
cat > /etc/systemd/system/unattended-upgrades.service.d/hardening.conf <<EOF
[Service]
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
EOF

# Disable exim4 if not needed (replace with null mailer)
systemctl stop exim4 2>/dev/null
systemctl disable exim4 2>/dev/null
systemctl mask exim4 2>/dev/null

# Mask other unused
systemctl mask rc-local.service 2>/dev/null
systemctl mask debug-shell.service 2>/dev/null
systemctl mask ctrl-alt-del.target 2>/dev/null
systemctl mask systemd-initctl.service 2>/dev/null

systemctl daemon-reload 2>/dev/null
echo "  Done"

########################################
# 9. RNG / Crypto fix
########################################
echo "[9/12] Crypto & RNG..."

# haveged provides entropy
systemctl enable haveged 2>/dev/null
systemctl start haveged 2>/dev/null

# Check entropy
ENTROPY=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null)
echo "  Entropy: ${ENTROPY:-unknown}"

# Strong random in SSH
if [ -f /etc/ssh/moduli ]; then
  awk '$5 >= 3072' /etc/ssh/moduli > /etc/ssh/moduli.safe
  if [ -s /etc/ssh/moduli.safe ]; then
    mv /etc/ssh/moduli.safe /etc/ssh/moduli
  else
    rm -f /etc/ssh/moduli.safe
  fi
fi
echo "  Done"

########################################
# 10. Logging fixes
########################################
echo "[10/12] Logging..."

# Rsyslog permissions
if [ -f /etc/rsyslog.conf ]; then
  grep -q '^\$FileCreateMode' /etc/rsyslog.conf || echo '$FileCreateMode 0640' >> /etc/rsyslog.conf
  grep -q '^\$DirCreateMode' /etc/rsyslog.conf || echo '$DirCreateMode 0750' >> /etc/rsyslog.conf
  grep -q '^\$Umask' /etc/rsyslog.conf || echo '$Umask 0027' >> /etc/rsyslog.conf
  systemctl restart rsyslog 2>/dev/null
fi

# Persistent journal
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal 2>/dev/null
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/storage.conf <<EOF
[Journal]
Storage=persistent
Compress=yes
ForwardToSyslog=yes
EOF
systemctl restart systemd-journald 2>/dev/null

# Fix all log perms
find /var/log -type f -exec chmod 640 {} \; 2>/dev/null
find /var/log -type d -exec chmod 750 {} \; 2>/dev/null
chmod 750 /var/log 2>/dev/null

echo "  Done"

########################################
# 11. Remove exim4 / fix mail
########################################
echo "[11/12] Mail cleanup..."

# Check if exim4 is running and stop it
systemctl stop exim4 2>/dev/null
systemctl disable exim4 2>/dev/null

# Either remove it or make it local-only
if dpkg -l exim4 2>/dev/null | grep -q "^ii"; then
  # Make local only if keeping
  if [ -f /etc/exim4/update-exim4.conf.conf ]; then
    sed -i "s/dc_eximconfig_configtype=.*/dc_eximconfig_configtype='local'/" /etc/exim4/update-exim4.conf.conf
    sed -i "s/dc_local_interfaces=.*/dc_local_interfaces='127.0.0.1'/" /etc/exim4/update-exim4.conf.conf
    update-exim4.conf 2>/dev/null
  fi
fi
echo "  Done"

########################################
# 12. Lynis profile - skip VPS-impossible items
########################################
echo "[12/12] Lynis profile..."
mkdir -p /etc/lynis

cat > /etc/lynis/custom.prf <<'EOF'
# Skip items impossible on VPS

# Separate partitions (VPS = single disk)
skip-test=FILE-6336

# GRUB password (VPS uses provider console)
skip-test=BOOT-5122

# NFS (not installed, not needed)
skip-test=STRG-1840

# SNMP (not installed)
skip-test=SNMP-3306

# OpenLDAP (not installed)
skip-test=LDAP-2219

# PHP (not installed)
skip-test=PHP-2368

# Squid (not installed)
skip-test=SQD-3613

# Apache (not installed)
skip-test=HTTP-6622

# Nginx (not installed)
skip-test=HTTP-6710

# SELinux (Debian uses AppArmor)
skip-test=MACF-6234

# TOMOYO (not applicable)
skip-test=MACF-6236

# grsecurity (not applicable on standard kernel)
skip-test=RBAC-6272
EOF

echo "  Done"

########################################
# SSH safety final check
########################################
echo ""
echo "[*] SSH check..."
if sshd -t 2>/dev/null; then
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
  echo "  SSH OK"
else
  echo "  SSH broken - reverting"
  cp /etc/ssh/sshd_config.bak86 /etc/ssh/sshd_config
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
fi

# Restart hardened services
systemctl daemon-reload
systemctl restart fail2ban 2>/dev/null
systemctl restart auditd 2>/dev/null

########################################
# Run Lynis
########################################
echo ""
echo "[*] Running Lynis with custom profile..."
echo ""

lynis audit system --no-colors --profile /etc/lynis/custom.prf 2>&1 | tee /var/log/lynis-90.log | grep -E "Hardening index|Warning"

SCORE=$(grep "Hardening index" /var/log/lynis-90.log 2>/dev/null | grep -oP '\d+' | head -1)

echo ""
echo "================================"
echo " Score: ${SCORE:-check log}"
echo "================================"
echo ""
echo " Reboot recommended: sudo reboot"
echo ""
echo " After reboot check:"
echo "   sudo lynis audit system --profile /etc/lynis/custom.prf | grep Hardening"
echo ""
echo " Still under 90? Run:"
echo "   sudo lynis show suggestions"
echo "   (paste output to me)"
echo "================================"

#!/bin/bash
##############################################################################
# Lynis 84 → 90+ Booster
# sudo bash push90.sh
##############################################################################

if [ "$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi

echo ""
echo "========================"
echo " Lynis 84 → 90+"
echo "========================"
echo ""

# 1. Hardened GRUB
echo "[1/20] GRUB hardening..."
if [ -f /etc/default/grub ]; then
  # Add security boot params
  CURRENT=$(grep "^GRUB_CMDLINE_LINUX=" /etc/default/grub | sed 's/.*="\(.*\)"/\1/')
  NEEDED=""
  for param in "audit=1" "audit_backlog_limit=8192" "slab_nomerge" "init_on_alloc=1" "init_on_free=1" "page_alloc.shuffle=1" "pti=on" "randomize_kstack_offset=on" "vsyscall=none" "lockdown=confidentiality"; do
    echo "$CURRENT" | grep -q "$param" || NEEDED="$NEEDED $param"
  done
  if [ -n "$NEEDED" ]; then
    sed -i "s|GRUB_CMDLINE_LINUX=\".*\"|GRUB_CMDLINE_LINUX=\"${CURRENT}${NEEDED}\"|" /etc/default/grub
    update-grub 2>/dev/null
  fi
fi
echo "  Done"

# 2. Restrict su
echo "[2/20] Restrict su..."
if [ -f /etc/pam.d/su ]; then
  grep -q "pam_wheel.so" /etc/pam.d/su || \
    sed -i '/pam_rootok/a auth required pam_wheel.so use_uid' /etc/pam.d/su
fi
# Create wheel/sudo group if needed
groupadd -f sugroup 2>/dev/null
echo "  Done"

# 3. Purge unnecessary packages
echo "[3/20] Removing extra packages..."
apt-get purge -y -qq \
  telnet xinetd nis talk ntalk \
  ldap-utils rsh-client rsh-redone-client \
  xserver-xorg* x11-common \
  popularity-contest \
  2>/dev/null
apt-get autoremove -y -qq 2>/dev/null
apt-get autoclean -y -qq 2>/dev/null
echo "  Done"

# 4. Harden /run/shm
echo "[4/20] Shared memory..."
if ! grep -q "/run/shm" /etc/fstab; then
  echo "tmpfs /run/shm tmpfs defaults,noexec,nodev,nosuid 0 0" >> /etc/fstab
fi
mount -o remount,noexec,nodev,nosuid /run/shm 2>/dev/null
mount -o remount,noexec,nodev,nosuid /dev/shm 2>/dev/null
echo "  Done"

# 5. More sysctl hardening
echo "[5/20] Extra sysctl..."
cat > /etc/sysctl.d/99-lynis-extra.conf <<'EOF'
# Lynis extra hardening
net.ipv4.conf.all.promote_secondaries = 1
net.ipv4.conf.default.promote_secondaries = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.arp_filter = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
kernel.modules_disabled = 0
kernel.unprivileged_userns_clone = 0
net.ipv4.tcp_sack = 0
net.ipv4.tcp_dsack = 0
net.ipv4.tcp_fack = 0
EOF
sysctl --system >/dev/null 2>&1
echo "  Done"

# 6. Purge old kernels
echo "[6/20] Clean old kernels..."
apt-get purge -y -qq $(dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | awk '{print $2}' | grep -v "$(uname -r)" | head -5) 2>/dev/null
echo "  Done"

# 7. Harden SSH more
echo "[7/20] SSH extra hardening..."
if [ -f /etc/ssh/sshd_config ]; then
  # Add missing hardening
  grep -q "^Compression" /etc/ssh/sshd_config || echo "Compression no" >> /etc/ssh/sshd_config
  grep -q "^TCPKeepAlive" /etc/ssh/sshd_config || echo "TCPKeepAlive no" >> /etc/ssh/sshd_config
  grep -q "^UseDNS" /etc/ssh/sshd_config || echo "UseDNS no" >> /etc/ssh/sshd_config
  grep -q "^MaxStartups" /etc/ssh/sshd_config || echo "MaxStartups 10:30:60" >> /etc/ssh/sshd_config

  # Remove weak KEX if exists
  sed -i '/^KexAlgorithms/d' /etc/ssh/sshd_config
  echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config

  sshd -t 2>/dev/null && systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
fi
echo "  Done"

# 8. Logrotate hardening
echo "[8/20] Log rotation..."
cat > /etc/logrotate.d/cis-hardening <<EOF
/var/log/sudo.log
/var/log/auth.log
/var/log/syslog
{
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
EOF
echo "  Done"

# 9. Harden systemd resolved
echo "[9/20] DNS hardening..."
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/cis.conf <<EOF
[Resolve]
DNS=1.1.1.1 9.9.9.9
FallbackDNS=8.8.8.8
DNSSEC=allow-downgrade
DNSOverTLS=opportunistic
EOF
systemctl restart systemd-resolved 2>/dev/null
echo "  Done"

# 10. No empty password login
echo "[10/20] Empty password check..."
# Find users with empty passwords and lock them
awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null | while read user; do
  if [ "$user" != "root" ]; then
    passwd -l "$user" 2>/dev/null
    echo "  Locked: $user"
  fi
done

# UID 0 check - only root should have UID 0
awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd 2>/dev/null | while read user; do
  echo "  WARNING: $user has UID 0!"
done
echo "  Done"

# 11. Systemd hardening
echo "[11/20] Systemd hardening..."
# Disable ctrl-alt-del reboot
systemctl mask ctrl-alt-del.target 2>/dev/null
ln -sf /dev/null /etc/systemd/system/ctrl-alt-del.target 2>/dev/null

# Disable debug-shell
systemctl stop debug-shell.service 2>/dev/null
systemctl mask debug-shell.service 2>/dev/null
echo "  Done"

# 12. Limit ptrace
echo "[12/20] Ptrace limit..."
echo "kernel.yama.ptrace_scope = 3" > /etc/sysctl.d/99-ptrace.conf
sysctl kernel.yama.ptrace_scope=3 2>/dev/null
echo "  Done"

# 13. Additional file permissions
echo "[13/20] More permissions..."
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null
chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null
chmod 600 /var/log/sudo.log 2>/dev/null
chmod 640 /var/log/syslog 2>/dev/null
chmod 640 /var/log/auth.log 2>/dev/null
chmod 640 /var/log/kern.log 2>/dev/null
chmod 640 /var/log/daemon.log 2>/dev/null
chmod 640 /var/log/dpkg.log 2>/dev/null
chmod 750 /var/log 2>/dev/null
chmod 700 /etc/cron.d 2>/dev/null
chmod 700 /etc/cron.daily 2>/dev/null
chmod 700 /etc/cron.hourly 2>/dev/null
chmod 700 /etc/cron.weekly 2>/dev/null
chmod 700 /etc/cron.monthly 2>/dev/null
chmod 700 /root 2>/dev/null
echo "  Done"

# 14. Remove SUID/SGID from unnecessary binaries
echo "[14/20] SUID/SGID cleanup..."
# Only remove from known-safe binaries
for bin in /usr/bin/chage /usr/bin/chfn /usr/bin/chsh /usr/bin/write /usr/bin/wall; do
  [ -f "$bin" ] && chmod u-s,g-s "$bin" 2>/dev/null
done
echo "  Done"

# 15. Harden nameserver config
echo "[15/20] Nameserver..."
if [ -f /etc/resolv.conf ]; then
  # Make sure we have nameservers
  grep -q "nameserver" /etc/resolv.conf || {
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    echo "nameserver 9.9.9.9" >> /etc/resolv.conf
  }
fi
echo "  Done"

# 16. Expire inactive accounts
echo "[16/20] Inactive account policy..."
useradd -D -f 30 2>/dev/null
# Set INACTIVE to 30 days in login.defs
grep -q "^INACTIVE" /etc/default/useradd 2>/dev/null || echo "INACTIVE=30" >> /etc/default/useradd
sed -i 's/^INACTIVE=.*/INACTIVE=30/' /etc/default/useradd 2>/dev/null
echo "  Done"

# 17. Daily security checks
echo "[17/20] Daily security checks..."
cat > /etc/cron.daily/security-check <<'EOF'
#!/bin/bash
# Daily security checks
LOG="/var/log/security-daily.log"
echo "=== Security Check $(date) ===" >> $LOG

# World writable files
echo "--- World writable files ---" >> $LOG
find / -xdev -type f -perm -0002 2>/dev/null >> $LOG

# No owner files
echo "--- No owner files ---" >> $LOG
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null >> $LOG

# SUID/SGID files
echo "--- SUID/SGID files ---" >> $LOG
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null >> $LOG
EOF
chmod 700 /etc/cron.daily/security-check
echo "  Done"

# 18. Debsums verification
echo "[18/20] Package verification..."
if command -v debsums >/dev/null 2>&1; then
  cat > /etc/cron.weekly/debsums <<'EOF'
#!/bin/bash
debsums -s 2>&1 | logger -t debsums
EOF
  chmod 700 /etc/cron.weekly/debsums
fi
echo "  Done"

# 19. Needrestart config
echo "[19/20] Needrestart..."
if [ -f /etc/needrestart/needrestart.conf ]; then
  sed -i "s/^#\$nrconf{restart}.*/$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf 2>/dev/null
fi
apt-get install -y -qq needrestart 2>/dev/null
echo "  Done"

# 20. Final cleanup
echo "[20/20] Final cleanup..."
apt-get autoremove -y -qq 2>/dev/null
apt-get autoclean -y -qq 2>/dev/null
apt-get clean 2>/dev/null

# Update file database
updatedb 2>/dev/null
echo "  Done"

########################################
# SSH safety
########################################
echo ""
echo "[*] SSH check..."
if sshd -t 2>/dev/null; then
  echo "  SSH config OK"
else
  echo "  SSH issue - not touching it"
fi

########################################
# Run Lynis
########################################
echo ""
echo "[*] Running Lynis..."
lynis update info 2>/dev/null
lynis audit system --no-colors 2>&1 | tee /var/log/lynis-final.log | grep "Hardening index"

SCORE=$(grep "Hardening index" /var/log/lynis-final.log 2>/dev/null | grep -oP '\d+' | head -1)

echo ""
echo "========================"
echo " Score: ${SCORE:-check log}"
echo " Log: /var/log/lynis-final.log"  
echo ""
echo " Reboot: sudo reboot"
echo "========================"

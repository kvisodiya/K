#!/bin/bash
##############################################################################
# Lynis Score Booster - Run AFTER start.sh
# Targets specific Lynis checks to push 77 -> 85+
# Usage: sudo bash boost.sh
##############################################################################

if [ "$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi

SSH_PORT="${SSH_PORT:-22}"

echo ""
echo "================================"
echo " Lynis Score Booster"
echo " Current: 77 → Target: 85+"
echo "================================"
echo ""

########################################
# 1. USB & Storage hardening
########################################
echo "[1/25] USB hardening..."
echo "install usb-storage /bin/true" > /etc/modprobe.d/disable-usb-storage.conf
echo "blacklist usb-storage" >> /etc/modprobe.d/disable-usb-storage.conf
echo "install firewire-core /bin/true" > /etc/modprobe.d/disable-firewire.conf
echo "blacklist firewire-core" >> /etc/modprobe.d/disable-firewire.conf
modprobe -r usb-storage 2>/dev/null
modprobe -r firewire-core 2>/dev/null
echo "  Done"

########################################
# 2. Compiler restrictions
########################################
echo "[2/25] Restricting compilers..."
if command -v gcc >/dev/null 2>&1; then
  chmod o-rx /usr/bin/gcc* 2>/dev/null
  chmod o-rx /usr/bin/cc 2>/dev/null
fi
if command -v g++ >/dev/null 2>&1; then
  chmod o-rx /usr/bin/g++* 2>/dev/null
fi
if command -v make >/dev/null 2>&1; then
  chmod o-rx /usr/bin/make 2>/dev/null
fi
echo "  Done"

########################################
# 3. Shell timeout (TMOUT)
########################################
echo "[3/25] Shell timeout..."
cat > /etc/profile.d/tmout.sh <<'EOF'
readonly TMOUT=900
export TMOUT
EOF
chmod 644 /etc/profile.d/tmout.sh

# Also in bashrc
grep -q "TMOUT" /etc/bash.bashrc 2>/dev/null || echo "TMOUT=900; export TMOUT; readonly TMOUT" >> /etc/bash.bashrc
echo "  Done"

########################################
# 4. Umask everywhere
########################################
echo "[4/25] Umask hardening..."
cat > /etc/profile.d/umask.sh <<'EOF'
umask 027
EOF
chmod 644 /etc/profile.d/umask.sh

sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs 2>/dev/null
grep -q "umask 027" /etc/bash.bashrc 2>/dev/null || echo "umask 027" >> /etc/bash.bashrc
grep -q "umask 027" /etc/profile 2>/dev/null || echo "umask 027" >> /etc/profile

# PAM umask
if [ -f /etc/pam.d/common-session ]; then
  grep -q "pam_umask" /etc/pam.d/common-session || echo "session optional pam_umask.so umask=027" >> /etc/pam.d/common-session
fi
echo "  Done"

########################################
# 5. /tmp hardening (bind mount with options)
########################################
echo "[5/25] /tmp hardening..."
# If /tmp is not a separate partition, use tmpfs
if ! mount | grep -q "on /tmp "; then
  grep -q "/tmp" /etc/fstab || echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /etc/fstab
fi

# /dev/shm hardening
if ! mount | grep -q "/dev/shm.*noexec"; then
  grep -q "/dev/shm" /etc/fstab || echo "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid 0 0" >> /etc/fstab
  mount -o remount,noexec,nodev,nosuid /dev/shm 2>/dev/null
fi

# /var/tmp bind to /tmp
grep -q "/var/tmp" /etc/fstab || echo "/tmp /var/tmp none bind 0 0" >> /etc/fstab
echo "  Done"

########################################
# 6. Process accounting
########################################
echo "[6/25] Process accounting..."
apt-get install -y -qq acct 2>/dev/null
if command -v accton >/dev/null 2>&1; then
  systemctl enable acct 2>/dev/null
  systemctl start acct 2>/dev/null
  touch /var/log/account/pacct 2>/dev/null
  accton on 2>/dev/null
fi
echo "  Done"

########################################
# 7. Sysstat
########################################
echo "[7/25] Sysstat..."
apt-get install -y -qq sysstat 2>/dev/null
if [ -f /etc/default/sysstat ]; then
  sed -i 's/ENABLED="false"/ENABLED="true"/' /etc/default/sysstat
  systemctl enable sysstat 2>/dev/null
  systemctl start sysstat 2>/dev/null
fi
echo "  Done"

########################################
# 8. Legal banners on ALL terminals
########################################
echo "[8/25] Legal banners..."
BANNER="Unauthorized access prohibited. All activity is logged and monitored."

echo "${BANNER}" > /etc/issue
echo "${BANNER}" > /etc/issue.net
echo "${BANNER}" > /etc/motd

# Remove default motd stuff
chmod -x /etc/update-motd.d/* 2>/dev/null
echo "  Done"

########################################
# 9. Sticky bit on world-writable dirs
########################################
echo "[9/25] Sticky bit fix..."
df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | while read dir; do
  find "$dir" -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | while read d; do
    chmod a+t "$d" 2>/dev/null
  done
done

# Fix world-writable files
df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | while read dir; do
  find "$dir" -xdev -type f -perm -0002 2>/dev/null | while read f; do
    chmod o-w "$f" 2>/dev/null
  done
done
echo "  Done"

########################################
# 10. Kernel hardening - extras
########################################
echo "[10/25] Extra kernel hardening..."
cat >> /etc/sysctl.d/99-cis.conf <<'EOF'

# Extra Lynis items
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.perf_event_paranoid = 3
net.ipv4.tcp_timestamps = 0
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
net.core.bpf_jit_harden = 2
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 2
dev.tty.ldisc_autoload = 0
vm.mmap_min_addr = 65536
vm.swappiness = 1
EOF
sysctl --system >/dev/null 2>&1
echo "  Done"

########################################
# 11. Disable core dumps properly
########################################
echo "[11/25] Core dumps..."
# limits.conf
grep -q "hard core" /etc/security/limits.conf 2>/dev/null || {
  echo "* hard core 0" >> /etc/security/limits.conf
  echo "* soft core 0" >> /etc/security/limits.conf
}

# systemd coredump
mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable.conf <<EOF
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

# sysctl
grep -q "fs.suid_dumpable" /etc/sysctl.d/99-cis.conf || echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-cis.conf
sysctl fs.suid_dumpable=0 2>/dev/null

# Profile
grep -q "ulimit -c 0" /etc/profile 2>/dev/null || echo "ulimit -c 0" >> /etc/profile
echo "  Done"

########################################
# 12. Harden /proc
########################################
echo "[12/25] /proc hardening..."
grep -q "hidepid" /etc/fstab || echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab
mount -o remount,hidepid=2 /proc 2>/dev/null
echo "  Done"

########################################
# 13. PAM hardening
########################################
echo "[13/25] PAM hardening..."

# Password remember
if [ -f /etc/pam.d/common-password ]; then
  grep -q "remember=" /etc/pam.d/common-password || \
    sed -i '/pam_unix.so/ s/$/ remember=5/' /etc/pam.d/common-password
  grep -q "sha512" /etc/pam.d/common-password || \
    sed -i '/pam_unix.so/ s/$/ sha512/' /etc/pam.d/common-password
fi

# Account lockout
if [ -f /etc/pam.d/common-auth ]; then
  grep -q "pam_tally2\|pam_faillock" /etc/pam.d/common-auth || {
    if [ -f /lib/x86_64-linux-gnu/security/pam_faillock.so ] || [ -f /usr/lib/x86_64-linux-gnu/security/pam_faillock.so ]; then
      sed -i '1i auth required pam_faillock.so preauth silent deny=5 unlock_time=900' /etc/pam.d/common-auth
    elif [ -f /lib/x86_64-linux-gnu/security/pam_tally2.so ] || [ -f /usr/lib/x86_64-linux-gnu/security/pam_tally2.so ]; then
      sed -i '1i auth required pam_tally2.so deny=5 onerr=fail unlock_time=900' /etc/pam.d/common-auth
    fi
  }
fi

# Delay after failed login
if [ -f /etc/pam.d/common-auth ]; then
  grep -q "pam_faildelay" /etc/pam.d/common-auth || \
    echo "auth optional pam_faildelay.so delay=4000000" >> /etc/pam.d/common-auth
fi
echo "  Done"

########################################
# 14. Secure single user mode
########################################
echo "[14/25] Single user mode..."
if [ -f /etc/shadow ]; then
  # Make sure root has a password (it should already)
  ROOT_PW=$(grep "^root:" /etc/shadow | cut -d: -f2)
  if [ "$ROOT_PW" = "*" ] || [ "$ROOT_PW" = "!" ] || [ -z "$ROOT_PW" ]; then
    echo "  WARNING: root has no password - single user mode is open"
  else
    echo "  Root password set"
  fi
fi

# Require auth for rescue/emergency
mkdir -p /etc/systemd/system/rescue.service.d
cat > /etc/systemd/system/rescue.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=-/lib/systemd/systemd-sulogin-shell rescue
EOF

mkdir -p /etc/systemd/system/emergency.service.d
cat > /etc/systemd/system/emergency.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=-/lib/systemd/systemd-sulogin-shell emergency
EOF
systemctl daemon-reload 2>/dev/null
echo "  Done"

########################################
# 15. AIDE (file integrity)
########################################
echo "[15/25] File integrity (AIDE)..."
apt-get install -y -qq aide aide-common 2>/dev/null
if command -v aideinit >/dev/null 2>&1; then
  if [ ! -f /var/lib/aide/aide.db ]; then
    echo "  Initializing AIDE database (background)..."
    aideinit --yes --force >/dev/null 2>&1 &
  else
    echo "  AIDE database exists"
  fi
  # Daily check cron
  cat > /etc/cron.daily/aide <<'EOF'
#!/bin/bash
/usr/bin/aide.wrapper --check
EOF
  chmod 700 /etc/cron.daily/aide
fi
echo "  Done"

########################################
# 16. Malware scanner
########################################
echo "[16/25] Malware scanners..."
apt-get install -y -qq rkhunter chkrootkit 2>/dev/null

# Configure rkhunter
if [ -f /etc/rkhunter.conf ]; then
  sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="yes"/' /etc/default/rkhunter 2>/dev/null
  sed -i 's/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf 2>/dev/null
  sed -i 's/^MIRRORS_MODE=.*/MIRRORS_MODE=0/' /etc/rkhunter.conf 2>/dev/null
  sed -i 's/^WEB_CMD=.*/WEB_CMD=""/' /etc/rkhunter.conf 2>/dev/null
  rkhunter --propupd 2>/dev/null
fi
echo "  Done"

########################################
# 17. Logging hardening
########################################
echo "[17/25] Logging..."

# Rsyslog file permissions
if [ -f /etc/rsyslog.conf ]; then
  grep -q "^\$FileCreateMode" /etc/rsyslog.conf || echo '$FileCreateMode 0640' >> /etc/rsyslog.conf
  grep -q "^\$DirCreateMode" /etc/rsyslog.conf || echo '$DirCreateMode 0750' >> /etc/rsyslog.conf
  systemctl restart rsyslog 2>/dev/null
fi

# Journald persistent
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/cis.conf <<EOF
[Journal]
Storage=persistent
Compress=yes
ForwardToSyslog=yes
EOF
systemctl restart systemd-journald 2>/dev/null

# Log directory permissions
chmod 750 /var/log 2>/dev/null
chmod 640 /var/log/syslog 2>/dev/null
chmod 640 /var/log/auth.log 2>/dev/null
chmod 640 /var/log/kern.log 2>/dev/null
echo "  Done"

########################################
# 18. NTP hardening
########################################
echo "[18/25] NTP..."
if [ -f /etc/chrony/chrony.conf ]; then
  grep -q "^pool" /etc/chrony/chrony.conf || {
    echo "pool 0.debian.pool.ntp.org iburst" >> /etc/chrony/chrony.conf
    echo "pool 1.debian.pool.ntp.org iburst" >> /etc/chrony/chrony.conf
  }
  systemctl restart chrony 2>/dev/null
fi
timedatectl set-ntp true 2>/dev/null
echo "  Done"

########################################
# 19. Audit hardening - extras
########################################
echo "[19/25] Extra audit rules..."
if [ -d /etc/audit/rules.d ]; then
  cat > /etc/audit/rules.d/cis-extra.rules <<'EOF'
# Extra rules for Lynis
-w /etc/apparmor/ -p wa -k apparmor
-w /etc/apparmor.d/ -p wa -k apparmor
-w /etc/localtime -p wa -k time-change
-w /etc/network -p wa -k network
-w /etc/hosts -p wa -k hosts
-w /etc/issue -p wa -k banner
-w /etc/issue.net -p wa -k banner
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/ -p wa -k security
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/profile -p wa -k profile
-w /etc/profile.d/ -p wa -k profile
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
EOF
  augenrules --load 2>/dev/null
  systemctl restart auditd 2>/dev/null
fi

# Audit config
if [ -f /etc/audit/auditd.conf ]; then
  sed -i 's/^max_log_file_action.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf 2>/dev/null
  sed -i 's/^space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf 2>/dev/null
  sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' /etc/audit/auditd.conf 2>/dev/null
fi

# Enable audit at boot
if [ -f /etc/default/grub ]; then
  if ! grep -q "audit=1" /etc/default/grub; then
    sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit=1 audit_backlog_limit=8192"/' /etc/default/grub
    update-grub 2>/dev/null
  fi
fi
echo "  Done"

########################################
# 20. Disable unused network protocols
########################################
echo "[20/25] Network protocols..."
for proto in dccp sctp rds tipc; do
  echo "install ${proto} /bin/true" > /etc/modprobe.d/disable-${proto}.conf
  echo "blacklist ${proto}" >> /etc/modprobe.d/disable-${proto}.conf
done
echo "  Done"

########################################
# 21. Sudo hardening
########################################
echo "[21/25] Sudo hardening..."
if [ -d /etc/sudoers.d ]; then
  cat > /etc/sudoers.d/cis-hardening <<'EOF'
# Log sudo commands
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output
Defaults use_pty
Defaults passwd_timeout=1
Defaults timestamp_timeout=5
EOF
  chmod 440 /etc/sudoers.d/cis-hardening
fi
touch /var/log/sudo.log
chmod 600 /var/log/sudo.log
echo "  Done"

########################################
# 22. Disable unused accounts
########################################
echo "[22/25] Unused accounts..."
# Lock system accounts that dont need login
for user in daemon bin sys games man lp mail news uucp proxy www-data backup list irc gnats nobody; do
  if id "$user" >/dev/null 2>&1; then
    usermod -s /usr/sbin/nologin "$user" 2>/dev/null
    passwd -l "$user" 2>/dev/null
  fi
done

# Set root shell explicitly
usermod -s /bin/bash root 2>/dev/null

# Lock accounts with no password
awk -F: '($2 == "" ) { print $1 }' /etc/shadow 2>/dev/null | while read user; do
  [ "$user" != "root" ] && passwd -l "$user" 2>/dev/null
done
echo "  Done"

########################################
# 23. Harden /home permissions
########################################
echo "[23/25] Home directory permissions..."
for dir in /home/*; do
  [ -d "$dir" ] && chmod 750 "$dir" 2>/dev/null
done
chmod 700 /root 2>/dev/null
echo "  Done"

########################################
# 24. Cron & at restrictions
########################################
echo "[24/25] Cron/at restrictions..."
echo "root" > /etc/cron.allow 2>/dev/null
echo "root" > /etc/at.allow 2>/dev/null
chmod 600 /etc/cron.allow 2>/dev/null
chmod 600 /etc/at.allow 2>/dev/null
rm -f /etc/cron.deny /etc/at.deny 2>/dev/null

# Permissions on cron dirs
chmod 600 /etc/crontab 2>/dev/null
chown root:root /etc/crontab 2>/dev/null
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
  [ -d "$d" ] && chmod 700 "$d" && chown root:root "$d" 2>/dev/null
done
echo "  Done"

########################################
# 25. AppArmor enforce all
########################################
echo "[25/25] AppArmor enforce..."
if command -v aa-enforce >/dev/null 2>&1; then
  aa-enforce /etc/apparmor.d/* 2>/dev/null
fi
systemctl enable apparmor 2>/dev/null
systemctl restart apparmor 2>/dev/null
echo "  Done"

########################################
# SSH safety check
########################################
echo ""
echo "[*] SSH safety check..."
if sshd -t 2>/dev/null; then
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
  echo "  SSH OK"
else
  echo "  SSH issue detected - not restarting (still running)"
fi

########################################
# Run Lynis
########################################
echo ""
echo "[*] Installing/updating Lynis..."
apt-get install -y -qq lynis 2>/dev/null

echo ""
echo "[*] Running Lynis audit..."
echo ""
lynis audit system --no-colors 2>&1 | tee /var/log/lynis-audit.log | grep -E "Hardening index|Warning|Suggestion" | head -30

# Get score
SCORE=$(grep "Hardening index" /var/log/lynis-audit.log 2>/dev/null | grep -oP '\d+' | head -1)

echo ""
echo "================================"
echo " DONE!"
echo "================================"
echo " Lynis Score: ${SCORE:-check /var/log/lynis-audit.log}"
echo " Full log:    /var/log/lynis-audit.log"
echo ""
echo " >>> sudo reboot (recommended) <<<"
echo "================================"

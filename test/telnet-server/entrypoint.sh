#!/bin/bash
set -e

echo "[entrypoint] Patching PAM..."

# Overwrite /etc/pam.d/login with a minimal container-safe version
cat > /etc/pam.d/login << 'PAM'
auth       optional   pam_faildelay.so delay=3000000
auth       requisite  pam_nologin.so
auth       required   pam_unix.so
account    required   pam_unix.so
session    optional   pam_motd.so motd=/run/motd.dynamic
session    required   pam_env.so readenv=1
session    required   pam_limits.so
session    optional   pam_mail.so standard
session    required   pam_unix.so
PAM

# Overwrite common-session — strip pam_systemd
cat > /etc/pam.d/common-session << 'PAM'
session [default=1]  pam_permit.so
session requisite    pam_deny.so
session required     pam_permit.so
session optional     pam_umask.so
session required     pam_unix.so
PAM

echo "[entrypoint] PAM patched."

# Overwrite inetd.conf completely — user=root is critical for PTY allocation
cat > /etc/inetd.conf << 'INETD'
23 stream tcp nowait root /usr/sbin/telnetd telnetd
INETD

echo "[entrypoint] inetd.conf written:"
cat /etc/inetd.conf

echo "[entrypoint] Starting inetd..."
exec /usr/sbin/inetd -d

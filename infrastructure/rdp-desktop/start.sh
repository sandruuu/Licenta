#!/bin/bash
set -e

# Update user credentials from environment if provided
if [ -n "$RDP_USER" ] && [ "$RDP_USER" != "admin" ]; then
    useradd -m -s /bin/bash "$RDP_USER" 2>/dev/null || true
    echo "$RDP_USER:$RDP_PASSWORD" | chpasswd
    adduser "$RDP_USER" sudo 2>/dev/null || true
    echo "xfce4-session" > "/home/$RDP_USER/.xsession"
    chown "$RDP_USER:$RDP_USER" "/home/$RDP_USER/.xsession"
fi

if [ -n "$RDP_PASSWORD" ] && [ "$RDP_USER" = "admin" ]; then
    echo "admin:$RDP_PASSWORD" | chpasswd
fi

# Clean stale PID files
rm -f /var/run/xrdp/xrdp-sesman.pid
rm -f /var/run/xrdp/xrdp.pid
rm -f /var/run/dbus/pid

# Start dbus
mkdir -p /var/run/dbus
dbus-daemon --system --fork 2>/dev/null || true

# Start XRDP session manager
/usr/sbin/xrdp-sesman

# Start XRDP in foreground
exec /usr/sbin/xrdp --nodaemon

#!/bin/bash
set -e

# Update user credentials from environment if provided
if [ -n "$SSH_USER" ] && [ "$SSH_USER" != "admin" ]; then
    useradd -m -s /bin/bash "$SSH_USER" 2>/dev/null || true
    echo "$SSH_USER:$SSH_PASSWORD" | chpasswd
    adduser "$SSH_USER" sudo 2>/dev/null || true
fi

if [ -n "$SSH_PASSWORD" ] && [ "$SSH_USER" = "admin" ]; then
    echo "admin:$SSH_PASSWORD" | chpasswd
fi

# Generate host keys if missing
ssh-keygen -A

# Start sshd in foreground
exec /usr/sbin/sshd -D -e

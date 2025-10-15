#!/bin/bash
# entrypoint.sh - create user with provided USERNAME and PASSWORD then start sshd
set -e

USERNAME="${USERNAME:-admin}"
PASSWORD="${PASSWORD:-password}"

# create user if not exists
if ! id -u "$USERNAME" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$USERNAME"
  echo "$USERNAME:$PASSWORD" | chpasswd
  usermod -aG sudo "$USERNAME"
fi

# Ensure SSHD config allows password auth (insecure on purpose for honeypot)
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true

/usr/sbin/sshd -D

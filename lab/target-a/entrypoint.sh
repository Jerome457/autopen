#!/bin/sh
set -eu

SECRET_FILE=/run/secrets/ssh_password
if [ ! -s "$SECRET_FILE" ]; then
    echo "SSH password secret is missing or empty." >&2
    exit 1
fi

IFS= read -r LAB_PASSWORD < "$SECRET_FILE"
printf '%s:%s\n' autopen-test "$LAB_PASSWORD" | chpasswd
unset LAB_PASSWORD

ssh-keygen -A >/dev/null
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config

#!/bin/sh
set -eu

SECRET_FILE=/run/secrets/ftp_password
if [ ! -s "$SECRET_FILE" ]; then
    echo "FTP password secret is missing or empty." >&2
    exit 1
fi

IFS= read -r LAB_PASSWORD < "$SECRET_FILE"
printf '%s:%s\n' autopen-ftp "$LAB_PASSWORD" | chpasswd
unset LAB_PASSWORD

exec /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf

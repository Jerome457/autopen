#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$LAB_DIR/.." && pwd)
SECRET_DIR="$LAB_DIR/secrets"
SSH_SECRET="$SECRET_DIR/ssh_password.txt"
FTP_SECRET="$SECRET_DIR/ftp_password.txt"
CANDIDATES="$PROJECT_DIR/data/lab_credentials.txt"

umask 077
mkdir -p "$SECRET_DIR" "$PROJECT_DIR/data"
chmod 700 "$SECRET_DIR"

if [ -e "$CANDIDATES" ] && [ ! -e "$SSH_SECRET" ]; then
    echo "Refusing to replace an existing candidate list without its matching SSH secret." >&2
    exit 1
fi

if [ ! -e "$SSH_SECRET" ]; then
    openssl rand -hex 18 > "$SSH_SECRET"
fi

if [ ! -e "$FTP_SECRET" ]; then
    while :; do
        openssl rand -hex 18 > "$FTP_SECRET"
        if ! cmp -s "$SSH_SECRET" "$FTP_SECRET"; then
            break
        fi
    done
fi

if [ ! -e "$CANDIDATES" ]; then
    TEMP_CANDIDATES=$(mktemp "$PROJECT_DIR/data/.lab_credentials.XXXXXX")
    {
        openssl rand -hex 12
        tr -d '\n' < "$SSH_SECRET"
        printf '\n'
        openssl rand -hex 12
    } > "$TEMP_CANDIDATES"
    mv "$TEMP_CANDIDATES" "$CANDIDATES"
fi

chmod 600 "$SSH_SECRET" "$FTP_SECRET" "$CANDIDATES"
echo "Lab secret files are ready; values were not displayed."

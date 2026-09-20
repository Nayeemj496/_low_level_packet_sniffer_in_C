#!/bin/sh
set -eu

certificate_dir=/etc/nginx/certs
certificate_file="$certificate_dir/nginx-selfsigned.crt"
key_file="$certificate_dir/nginx-selfsigned.key"

mkdir -p "$certificate_dir"

if [ ! -s "$certificate_file" ] || [ ! -s "$key_file" ] || \
    ! openssl x509 -in "$certificate_file" -noout -checkhost nginx >/dev/null 2>&1; then
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$key_file" \
        -out "$certificate_file" \
        -days 365 \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,DNS:nginx,IP:127.0.0.1"
    chmod 600 "$key_file"
fi
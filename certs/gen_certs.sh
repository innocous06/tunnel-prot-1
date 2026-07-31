#!/bin/bash
# gen_certs.sh — Generate the private CA and certificates for the tunnel.
# Run this ONCE on your local machine. Keep all private keys out of VCS.
#
# Output layout:
#   certs/
#     ca-key.pem          ← CA private key (NEVER share or upload)
#     ca-cert.pem         ← CA certificate (upload to every VPS, embed in client)
#     server-key.pem      ← Server private key (upload to the VPS only)
#     server-cert.pem     ← Server certificate (upload to the VPS only)
#     device-laptop-key.pem   ← Client key for your laptop
#     device-laptop-cert.pem  ← Client cert for your laptop
#     device-phone-key.pem    ← Client key for your phone
#     device-phone-cert.pem   ← Client cert for your phone
#
# Usage:
#   chmod +x gen_certs.sh
#   ./gen_certs.sh in.yourdomain.com    ← pass your VPS domain as $1
#
# Requires: openssl (any modern version)

set -e

SERVER_DOMAIN="${1:-vpn.example.com}"
OUT="certs"
mkdir -p "$OUT"

echo "==> Generating private CA..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$OUT/ca-key.pem"
openssl req -new -x509 -days 3650 -key "$OUT/ca-key.pem" \
  -subj "/CN=TunnelCA" \
  -out "$OUT/ca-cert.pem"

echo "==> Generating server cert for $SERVER_DOMAIN..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$OUT/server-key.pem"
openssl req -new -key "$OUT/server-key.pem" \
  -subj "/CN=$SERVER_DOMAIN" \
  -out "$OUT/server.csr"
openssl x509 -req -days 825 \
  -in "$OUT/server.csr" \
  -CA "$OUT/ca-cert.pem" -CAkey "$OUT/ca-key.pem" -CAcreateserial \
  -extfile <(printf "subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth" "$SERVER_DOMAIN") \
  -out "$OUT/server-cert.pem"
rm "$OUT/server.csr"

echo "==> Generating client cert for device: laptop..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$OUT/device-laptop-key.pem"
openssl req -new -key "$OUT/device-laptop-key.pem" \
  -subj "/CN=device-laptop" \
  -out "$OUT/device-laptop.csr"
openssl x509 -req -days 825 \
  -in "$OUT/device-laptop.csr" \
  -CA "$OUT/ca-cert.pem" -CAkey "$OUT/ca-key.pem" -CAcreateserial \
  -extfile <(printf "extendedKeyUsage=clientAuth") \
  -out "$OUT/device-laptop-cert.pem"
rm "$OUT/device-laptop.csr"

echo "==> Generating client cert for device: phone..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$OUT/device-phone-key.pem"
openssl req -new -key "$OUT/device-phone-key.pem" \
  -subj "/CN=device-phone" \
  -out "$OUT/device-phone.csr"
openssl x509 -req -days 825 \
  -in "$OUT/device-phone.csr" \
  -CA "$OUT/ca-cert.pem" -CAkey "$OUT/ca-key.pem" -CAcreateserial \
  -extfile <(printf "extendedKeyUsage=clientAuth") \
  -out "$OUT/device-phone-cert.pem"
rm "$OUT/device-phone.csr"

echo ""
echo "==> Done! Files in $OUT/:"
ls -1 "$OUT/"
echo ""
echo "==> IMPORTANT: Upload to each VPS:"
echo "      ca-cert.pem  server-cert.pem  server-key.pem"
echo "    Keep on this machine only:"
echo "      ca-key.pem  device-*-key.pem"
echo "    Bundle with each client binary:"
echo "      ca-cert.pem  device-laptop-cert.pem  device-laptop-key.pem"

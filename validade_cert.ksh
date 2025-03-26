#!/bin/bash

FILE=$1
if [ -z "$FILE" ]; then
  echo "Usage: $0 <certificate_chain_file>"
  exit 1
fi

# Clean up previous runs
rm -f cert_*.pem

awk '
  /-----BEGIN CERTIFICATE-----/ {
    f = sprintf("cert_%02d.pem", n++);
  }
  f != "" {
    print > f
  }
' "$FILE"

echo "Analyzing certificate chain in: $FILE"
echo "---------------------------------------------"

for CERT in cert_*.pem; do
  SUBJECT=$(openssl x509 -in "$CERT" -noout -subject | sed 's/subject= //')
  ISSUER=$(openssl x509 -in "$CERT" -noout -issuer | sed 's/issuer= //')

  if openssl verify -CAfile "$CERT" "$CERT" 2>/dev/null | grep -q ": OK"; then
    FLAG="(SELF-SIGNED)"
  else
    FLAG=""
  fi

  echo "→ $CERT"
  echo "  Subject: $SUBJECT"
  echo "  Issuer : $ISSUER $FLAG"
  echo ""
done

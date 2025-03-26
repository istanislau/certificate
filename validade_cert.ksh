#!/bin/bash

FILE=$1
if [ -z "$FILE" ]; then
  echo "Usage: $0 <certificate_chain_file>"
  exit 1
fi

# Clean up previous runs
rm -f cert_*.pem

# Extract certificates directly into the current directory
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

  # Detect if subject and issuer match
  SUBJECT_NORM=$(echo "$SUBJECT" | tr -d '[:space:]')
  ISSUER_NORM=$(echo "$ISSUER" | tr -d '[:space:]')
  SELF_SIGNED_GUESS=false
  if [ "$SUBJECT_NORM" = "$ISSUER_NORM" ]; then
    SELF_SIGNED_GUESS=true
  fi

  # Check if it's a valid self-signed CA
  if openssl verify -CAfile "$CERT" "$CERT" 2>/dev/null | grep -q ": OK"; then
    FLAG="(SELF-SIGNED)"
  elif [ "$SELF_SIGNED_GUESS" = true ]; then
    FLAG="(SELF-SIGNED Not trusted as CA)"
  else
    FLAG=""
  fi

  # Check for Basic Constraints and CA:TRUE (AIX-compatible)
  BASIC_CONSTRAINTS=$(openssl x509 -in "$CERT" -text -noout | \
    awk '/X509v3 Basic Constraints/,/X509v3/ { if ($0 ~ /CA:/) { gsub(/ /, "", $2); print $2 } }' | head -n1)

  if [ "$BASIC_CONSTRAINTS" = "TRUE" ]; then
    CA_FLAG="CA Capable: YES"
  else
    CA_FLAG="CA Capable: NO"
  fi

  echo "→ $CERT"
  echo "  Subject: $SUBJECT"
  echo "  Issuer : $ISSUER $FLAG"
  echo "  $CA_FLAG"
  echo ""
done

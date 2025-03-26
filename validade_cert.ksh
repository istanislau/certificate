#!/bin/bash

FILE=$1
if [ -z "$FILE" ]; then
  echo "Usage: $0 <certificate_chain_file>"
  exit 1
fi

# Get base filename without extension
BASE_NAME=$(basename "$FILE" .pem | sed 's/\.[^.]*$//')

# Clean up previous runs
rm -f ${BASE_NAME}_cert_*.pem
rm -f ${BASE_NAME}_subjects.txt

# Extract certificates directly into the current directory
awk -v prefix="${BASE_NAME}_cert_" '
  /-----BEGIN CERTIFICATE-----/ {
    f = sprintf("%s%02d.pem", prefix, n++); inside=1
  }
  inside {
    print > f
  }
  /-----END CERTIFICATE-----/ {
    inside=0
  }
' "$FILE"

echo "Analyzing certificate chain in: $FILE"
echo "---------------------------------------------"

# Build the full CA file from all certs
cat ${BASE_NAME}_cert_*.pem > full_chain.pem

for CERT in ${BASE_NAME}_cert_*.pem; do
  SUBJECT=$(openssl x509 -in "$CERT" -noout -subject | sed 's/subject= //')
  ISSUER=$(openssl x509 -in "$CERT" -noout -issuer | sed 's/issuer= //')

  echo "$SUBJECT" | sed 's/^subject= //' >> ${BASE_NAME}_subjects.txt

  # Normalize subject and issuer for comparison
  SUBJECT_NORM=$(echo "$SUBJECT" | tr -d '[:space:]')
  ISSUER_NORM=$(echo "$ISSUER" | tr -d '[:space:]')
  IS_SELF_SIGNED=""
  WARNING=""

  # Check if the certificate validates itself
  VERIFY_SELF=$(openssl verify -CAfile "$CERT" "$CERT" 2>&1)
  VERIFY_CHAIN=$(openssl verify -CAfile full_chain.pem "$CERT" 2>&1)

  if echo "$VERIFY_SELF" | grep -q ": OK"; then
    if [ "$SUBJECT_NORM" = "$ISSUER_NORM" ]; then
      IS_SELF_SIGNED="(SELF-SIGNED)"
    else
      IS_SELF_SIGNED="(Self-issued but not self-signed)"
    fi
  elif [ "$SUBJECT_NORM" = "$ISSUER_NORM" ]; then
    IS_SELF_SIGNED="(SELF-SIGNED Not trusted as CA)"
    WARNING=" Self-issued cert that fails verification — may trigger ORA-29024 or error 19"
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
  echo "  Issuer : $ISSUER $IS_SELF_SIGNED"
  echo "  $CA_FLAG"
  echo "  OpenSSL self-verify: $VERIFY_SELF"
  echo "  OpenSSL chain-verify (against full chain): $VERIFY_CHAIN"
  [ -n "$WARNING" ] && echo "  $WARNING"
  echo ""
done

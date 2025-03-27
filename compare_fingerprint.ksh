#!/bin/bash

CHAIN_PREFIX=$1
WALLET_PREFIX=$2

if [ -z "$CHAIN_PREFIX" ] || [ -z "$WALLET_PREFIX" ]; then
  echo "Usage: $0 <chain_cert_prefix> <wallet_cert_prefix>"
  echo "Example: $0 cadeia_cert wallet_cert"
  exit 1
fi

echo "Comparando fingerprints SHA1 dos certificados da cadeia com os da wallet"
echo "======================================================================="

for CERT in ${CHAIN_PREFIX}_cert_*.pem; do
  echo "→ $CERT"
  CERT_FP=$(openssl x509 -in "$CERT" -noout -fingerprint -sha1 | sed 's/^.*=//')
  MATCHED="❌ NÃO encontrado na wallet"
  for WALLET_CERT in ${WALLET_PREFIX}_cert_*.pem; do
    WALLET_FP=$(openssl x509 -in "$WALLET_CERT" -noout -fingerprint -sha1 | sed 's/^.*=//')
    if [ "$CERT_FP" = "$WALLET_FP" ]; then
      MATCHED="✅ Match com $WALLET_CERT"
      break
    fi
  done
  echo "   → Resultado: $MATCHED"
  echo ""
done

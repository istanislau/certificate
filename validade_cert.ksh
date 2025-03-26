#!/bin/bash

FILE=$1
if [ -z "$FILE" ]; then
  echo "Usage: $0 <certificate_chain_file>"
  exit 1
fi

mkdir -p tmp_cert_analysis
cd tmp_cert_analysis || exit 1

# Extract certificate blocks and save them into separate files
awk 'BEGIN{n=0} /-----BEGIN CERTIFICATE-----/{f=sprintf("cert_%02d.pem", n++);} {print > f}' "../$FILE"

echo "Analyzing certificate chain in: $FILE"
echo "---------------------------------------------"

for CERT in cert_*.pem; do
  SUBJECT=$(openssl x509 -in "$CERT" -noout -subject | sed 's/subject= //')
  ISSUER=$(openssl x509 -in "$CERT" -noout -issuer | sed 's/issuer= //')

  if [ "$SUBJECT" = "$ISSUER" ]; then
    FLAG="(SELF-SIGNED)"
  else
    FLAG=""
  fi

  echo "→ $CERT"
  echo "  Subject: $SUBJECT"
  echo "  Issuer : $ISSUER $FLAG"
  echo ""
done

cd ..
rm -rf tmp_cert_analysis

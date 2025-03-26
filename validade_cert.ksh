#!/bin/bash

ARQUIVO=$1
if [ -z "$ARQUIVO" ]; then
  echo "Uso: $0 <arquivo_com_cadeia>"
  exit 1
fi

mkdir -p tmp_cert_analysis
cd tmp_cert_analysis || exit 1

# Extrai os blocos e salva em arquivos separados
awk 'BEGIN{n=0} /-----BEGIN CERTIFICATE-----/{f=sprintf("cert_%02d.pem", n++);} {print > f}' "../$ARQUIVO"

echo "Analisando cadeia de certificados em: $ARQUIVO"
echo "---------------------------------------------"

for FILE in cert_*.pem; do
  SUBJECT=$(openssl x509 -in "$FILE" -noout -subject | sed 's/subject= //')
  ISSUER=$(openssl x509 -in "$FILE" -noout -issuer | sed 's/issuer= //')

  if [ "$SUBJECT" = "$ISSUER" ]; then
    FLAG="(SELF-SIGNED)"
  else
    FLAG=""
  fi

  echo "→ $FILE"
  echo "  Subject: $SUBJECT"
  echo "  Issuer : $ISSUER $FLAG"
  echo ""
done

cd ..
rm -rf tmp_cert_analysis

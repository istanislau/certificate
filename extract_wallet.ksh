#!/bin/bash

# Hardcoded values
WALLET_PATH="/caminho/da/sua/wallet"
PASSWORD="suasenha"
SUBJECTS_FILE=$1

if [ -z "$SUBJECTS_FILE" ]; then
  echo "Usage: $0 <subjects_file>"
  exit 1
fi

if [ ! -f "$SUBJECTS_FILE" ]; then
  echo "$SUBJECTS_FILE not found. Run the analysis script first."
  exit 1
fi

COUNT=0
while IFS= read -r DN; do
  SAFE_NAME=$(echo "$DN" | tr -dc '[:alnum:]' | cut -c1-40)
  OUTPUT_FILE="wallet_cert_${COUNT}_${SAFE_NAME}.pem"
  echo "Exporting: $DN → $OUTPUT_FILE"
  orapki wallet export -wallet "$WALLET_PATH" -dn "$DN" -cert "$OUTPUT_FILE" -pwd "$PASSWORD" 2>/dev/null

  if [ $? -ne 0 ]; then
    echo "  ❌ Failed to export cert with DN: $DN"
    rm -f "$OUTPUT_FILE"
  fi

  COUNT=$((COUNT + 1))
done < "$SUBJECTS_FILE"

echo "Done. Exported $COUNT certificate(s)."

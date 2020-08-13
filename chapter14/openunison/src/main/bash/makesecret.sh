#!/bin/bash

OU_ENV_B64=`base64 -w 0 < $1/ou.env`
KS_B64=`base64 -w 0 < $1/unisonKeyStore.jks`
OU_YAML=`base64 -w 0 < $1/openunison.yaml`

cat << EOF
apiVersion: v1
kind: Secret
metadata:
  name: openunison-secrets
data:
  ou.env: $OU_ENV_B64
  unisonKeyStore.jks: $KS_B64
  openunison.yaml: $OU_YAML
EOF

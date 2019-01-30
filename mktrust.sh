#!/bin/sh

if [ $# -ne 1 ]; then
    echo "usage: $0 crt" >&2
    exit 64
fi

crt=$(base64 -w 0 <$1)

cat - <<EOF
---
apiVersion: v1
kind: Secret
metadata:
  name: l5d-id-trust
  labels:
    demo: l5d-id
type: Opaque
data:
    trust.crt: $crt
EOF

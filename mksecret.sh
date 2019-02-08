#!/bin/sh

if [ $# -ne 2 ]; then
    echo "usage: $0 key crt" >&2
    exit 64
fi

if [ "$(uname -s)" = "Darwin" ]; then
    key=$(base64 <$1)
    crt=$(base64 <$2)
else
    key=$(base64 -w 0 <$1)
    crt=$(base64 -w 0 <$2)
fi

cat - <<EOF
---
apiVersion: v1
kind: Secret
metadata:
  name: l5d-id-signing-key
  labels:
    demo: l5d-id
    l5d-role: controller
type: Opaque
data:
    key: $key
    crt: $crt
EOF

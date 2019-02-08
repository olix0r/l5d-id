#!/bin/sh

if [ $# -ne 1 ]; then
    echo "usage: $0 crt" >&2
    exit 64
fi

if [ "$(uname -s)" = "Darwin" ]; then
    crt=$(base64 <"$1")
else
    crt=$(base64 -w 0 <"$1")
fi

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

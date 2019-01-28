FROM golang:1.11.5 as build
WORKDIR /go/src/github.com/olix0r/l5d-id
COPY cmd cmd
COPY gen gen
COPY vendor vendor
RUN CGO_ENABLED=0 GOOS=linux go install ./cmd/...

FROM debian:jessie-slim
COPY --from=build /go/bin/svc /l5d-id-svc
COPY --from=build /go/bin/sync-init /l5d-id-sync-init
COPY --from=build /go/bin/sync /l5d-id-sync

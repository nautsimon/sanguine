FROM alpine:latest as builder

RUN apk add --no-cache ca-certificates
RUN update-ca-certificates

FROM alpine:latest

LABEL org.label-schema.description="Explorer Docker file"
LABEL org.label-schema.name="ghcr.io/synapsecns/sanguine/explorer"
LABEL org.label-schema.schema-version="1.0.0"
LABEL org.label-schema.vcs-url="https://github.com/synapsecns/sanguine"
LABEL org.opencontainers.image.source="https://github.com/synapsecns/sanguine"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

WORKDIR /app
COPY explorer /app/explorer

ENTRYPOINT ["/app/explorer"]

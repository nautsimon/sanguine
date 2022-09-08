# TODO: we should use alpine here
FROM ubuntu:latest

LABEL org.label-schema.description="Scribe Docker file"
LABEL org.label-schema.name="ghcr.io/synapsecns/sanguine/scribe"
LABEL org.label-schema.schema-version="1.0.0"
LABEL org.label-schema.vcs-url="https://github.com/synapsecns/sanguine"
LABEL org.opencontainers.image.source="https://github.com/synapsecns/sanguine"

RUN apt-get update
RUN apt-get install ca-certificates -y
RUN update-ca-certificates

WORKDIR /app
COPY scribe /app/scribe

ENTRYPOINT ["/app/scribe"]

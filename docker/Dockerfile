FROM cyberark.jfrog.io/dockerhub-remote/alpine:3.19

ARG BUILD_VERSION=v0.0.0-dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="idsec" \
      org.opencontainers.image.source="https://github.com/cyberark/idsec-cli-golang" \
      org.opencontainers.image.documentation="https://github.com/cyberark/idsec-cli-golang/blob/main/README.md" \
      org.opencontainers.image.version="${BUILD_VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

RUN apk add --no-cache ca-certificates && \
    addgroup -S idsec-cli && \
    adduser -S -D -G idsec-cli -h /home/idsec-cli -s /bin/sh idsec-cli && \
    mkdir -p /idsec/profiles /idsec/keyring /data && \
    chown -R idsec-cli:idsec-cli /idsec /home/idsec-cli /data

ENV IDSEC_PROFILES_FOLDER=/idsec/profiles
ENV IDSEC_KEYRING_FOLDER=/idsec/keyring

COPY --chmod=0755 idsec /usr/local/bin/idsec

USER idsec-cli
WORKDIR /data

ENTRYPOINT ["idsec"]
CMD ["--help"]

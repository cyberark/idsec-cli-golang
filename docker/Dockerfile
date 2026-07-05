# --- Builder stage ---
FROM --platform=$BUILDPLATFORM cyberark.jfrog.io/dockerhub-remote/golang:1.24 AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

ARG BUILD_VERSION=v0.0.0-dev
ARG BUILD_NUMBER=0
ARG GIT_COMMIT=unknown
ARG GIT_BRANCH=unknown
ARG BUILD_DATE=unknown
ARG RELEASED_FEATURES_ONLY=true

WORKDIR /app

COPY . .

RUN set -eux; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -mod=vendor -buildvcs=false \
    -ldflags="-s -w \
      -X 'github.com/cyberark/idsec-sdk-golang/pkg/config.gitCommit=${GIT_COMMIT}' \
      -X 'github.com/cyberark/idsec-sdk-golang/pkg/config.gitBranch=${GIT_BRANCH}' \
      -X 'github.com/cyberark/idsec-sdk-golang/pkg/config.buildDate=${BUILD_DATE}' \
      -X 'github.com/cyberark/idsec-sdk-golang/pkg/config.version=${BUILD_VERSION}' \
      -X 'github.com/cyberark/idsec-sdk-golang/pkg/config.buildNumber=${BUILD_NUMBER}' \
      -X 'github.com/cyberark/idsec-sdk-golang/pkg/config.repoPath=cyberark/idsec-cli-golang' \
      -X 'github.com/cyberark/idsec-cli-golang/pkg/registry.releasedFeaturesOnly=${RELEASED_FEATURES_ONLY}'" \
    -o /app/idsec \
    ./cmd/idsec/idsec.go; \
    chmod +x /app/idsec

# --- Runtime stage ---
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

COPY --from=builder --chmod=0755 /app/idsec /usr/local/bin/idsec

USER idsec-cli
WORKDIR /data

ENTRYPOINT ["idsec"]
CMD ["--help"]

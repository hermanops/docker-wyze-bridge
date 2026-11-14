# ── Stage 1: Fetch go2rtc binary + video-rtc.js ─────────────────────────────
FROM alpine:3.21 AS go2rtc-fetch
ARG GO2RTC_VERSION=1.9.14
ARG TARGETARCH
RUN apk add --no-cache curl ca-certificates && \
    ARCH=${TARGETARCH}; \
    if [ "$ARCH" = "arm" ]; then ARCH="arm"; fi; \
    curl -fsSL \
      "https://github.com/AlexxIT/go2rtc/releases/download/v${GO2RTC_VERSION}/go2rtc_linux_${ARCH}" \
      -o /go2rtc && \
    chmod +x /go2rtc && \
    curl -fsSL \
      "https://github.com/AlexxIT/go2rtc/raw/v${GO2RTC_VERSION}/www/video-rtc.js" \
      -o /video-rtc.js

# ── Stage 2: Build Go binary ──────────────────────────────────────────────────
FROM golang:1.26.2-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Replace placeholder video-rtc.js with real one before embedding
COPY --from=go2rtc-fetch /video-rtc.js ./internal/webui/static/video-rtc.js
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-s -w -X main.Version=${VERSION}" \
    -o /wyze-bridge ./cmd/wyze-bridge

# ── Stage 3: Runtime ──────────────────────────────────────────────────────────
FROM alpine:3.21
# ffmpeg is used by:
#   1. go2rtc's /api/frame.jpeg snapshot endpoint (JPEG frame extraction)
#   2. the recording subsystem (per-camera recording processes)
# Keep ffmpeg installed when snapshots or recording are required.
RUN apk add --no-cache ca-certificates tzdata ffmpeg && \
    mkdir -p /config /media/snapshots /media/recordings

COPY --from=builder      /wyze-bridge   /usr/local/bin/wyze-bridge
COPY --from=go2rtc-fetch /go2rtc        /usr/local/bin/go2rtc

EXPOSE 5080
EXPOSE 1984
EXPOSE 8554
EXPOSE 8888
EXPOSE 8889
EXPOSE 8189/udp

VOLUME ["/config", "/media"]

ENTRYPOINT ["/usr/local/bin/wyze-bridge"]

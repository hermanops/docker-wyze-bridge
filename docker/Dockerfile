# ── Stage 1: Fetch go2rtc binary + video-rtc.js ─────────────────────────────
FROM alpine:3.21@sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab AS go2rtc-fetch
ARG GO2RTC_VERSION=1.9.14
ARG TARGETARCH
ENV GO2RTC_COMMIT=b5948cfb25404cc5cb37b166ecaa2dca20b11d4b
ENV GO2RTC_SHA256_AMD64=32d616af226bd731678ffde328b94cfb94e30339bfefc469cfb76323144615a6
ENV GO2RTC_SHA256_ARM64=359fabade8a7a51e81a55fe6df6b0ef81764a5e1d63179577534eaaa71904b50
ENV GO2RTC_SHA256_ARM=4d7e1639af5a2722a28e864468fd8099b3c1682565446c798bf9e3b38fde12e4
ENV VIDEO_RTC_SHA256=d48ce627baf7c341a92c0f5844a3c546431f9db873ff21489671aba2ecfe64fb
COPY docker/verify-sha256.sh /verify-sha256.sh
RUN apk add --no-cache curl ca-certificates && \
    case "$TARGETARCH" in \
      amd64) CHECKSUM="$GO2RTC_SHA256_AMD64" ;; \
      arm64) CHECKSUM="$GO2RTC_SHA256_ARM64" ;; \
      arm) CHECKSUM="$GO2RTC_SHA256_ARM" ;; \
      *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    curl -fsSL \
      "https://github.com/AlexxIT/go2rtc/releases/download/v${GO2RTC_VERSION}/go2rtc_linux_${TARGETARCH}" \
      -o /go2rtc && \
    sh /verify-sha256.sh /go2rtc "$CHECKSUM" && \
    chmod +x /go2rtc && \
    curl -fsSL \
      "https://raw.githubusercontent.com/AlexxIT/go2rtc/${GO2RTC_COMMIT}/www/video-rtc.js" \
      -o /video-rtc.js && \
    sh /verify-sha256.sh /video-rtc.js "$VIDEO_RTC_SHA256"

# ── Stage 2: Build Go binary ──────────────────────────────────────────────────
FROM golang:1.26.2-alpine@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS builder
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
FROM alpine:3.21@sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab
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

# Build stage
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS builder

ARG VERSION=dev
ARG BUILD_DATE=unknown

ARG TARGETPLATFORM
ARG TARGETARCH
ARG TARGETOS

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY *.go ./

# Build the application for the target platform
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-X main.version=${VERSION} -X main.buildDate=${BUILD_DATE}" -a -installsuffix cgo -o geo-guardian .

# Runtime stage
FROM alpine:latest

ARG VERSION=dev
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.version="$VERSION" \
	org.opencontainers.image.created="$BUILD_DATE"

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/geo-guardian .

# Run as an unprivileged user. The binary gets CAP_NET_BIND_SERVICE so it can
# still listen on the default port 80 on runtimes that don't lower
# net.ipv4.ip_unprivileged_port_start for containers (e.g. Kubernetes).
RUN addgroup -S -g 10001 geoguardian \
	&& adduser -S -D -H -u 10001 -G geoguardian -s /sbin/nologin geoguardian \
	&& apk --no-cache add libcap \
	&& setcap cap_net_bind_service=+ep /app/geo-guardian \
	&& apk del libcap

USER 10001:10001

EXPOSE 80

CMD ["/app/geo-guardian"]

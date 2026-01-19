# Build stage
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

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

RUN apk --no-cache add ca-certificates

WORKDIR /root/

LABEL org.opencontainers.image.version="$VERSION" \
	org.opencontainers.image.created="$BUILD_DATE"

# Copy the binary from builder
COPY --from=builder /app/geo-guardian .

EXPOSE 80

CMD ["./geo-guardian"]

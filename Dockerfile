# ---------- build stage ----------
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Enable static binary
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Copy module files first (better caching)
COPY go.mod go.sum  ./
RUN go mod download


# Copy source
COPY *.go ./
COPY internal ./internal

# Build
RUN go build -o elasticgateway


# ---------- runtime stage ----------
FROM gcr.io/distroless/static:nonroot

WORKDIR /app

# Copy binary
COPY --from=builder /app/elasticgateway /app/elasticgateway

# Mount ROOT_CA only when endpoints use a private certificate authority.
EXPOSE 8080


ENTRYPOINT ["/app/elasticgateway"]

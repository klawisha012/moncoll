# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# Final stage: debian:12-slim so that openssl and certbot binaries are
# available at runtime. The cert core (internal/certs) shells out to both,
# mirroring the Python backend which relies on them inside the container.
# uid 1000 matches the compose USER directive and the existing gobackend
# uid-1000 run constraint (see commit cbbfb98).
FROM debian:12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssl \
        certbot \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 1000 appuser && useradd -u 1000 -g 1000 -M -s /usr/sbin/nologin appuser
COPY --from=build /out/server /server
USER 1000
EXPOSE 8080
ENTRYPOINT ["/server"]

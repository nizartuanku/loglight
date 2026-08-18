# Loglight — minimal production image.
# Build:  docker build -t loglight .
# Run:    docker run -d -p 127.0.0.1:8427:8427 -p 5514:5514/udp -v loglight-data:/data loglight

FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO is required by the mattn/go-sqlite3 driver used in this build.
ARG ISSUER_PUBKEY=""
RUN CGO_ENABLED=1 go build -trimpath \
    -ldflags "-s -w -X main.issuerPublicKeyB64=${ISSUER_PUBKEY}" \
    -o /out/loglight ./cmd/loglight

FROM debian:bookworm-slim
RUN useradd -r -u 10001 loglight \
 && apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/loglight /usr/local/bin/loglight
USER loglight
VOLUME /data
EXPOSE 8427
ENTRYPOINT ["loglight", "-listen", "0.0.0.0:8427", "-db", "/data/loglight.db", "-license", "/data/loglight-license.key"]

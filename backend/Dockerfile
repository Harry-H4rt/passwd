# Multi-stage build for the passwd backend. Pure-Go SQLite (no cgo) means a fully
# static binary, so the final image is tiny and needs no C runtime.

FROM golang:1.22-alpine AS build
WORKDIR /src
# Cache deps first.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/passwd-server ./cmd/server

FROM alpine:3.20
# Run as an unprivileged user. Creating /data in the image means a fresh named
# volume inherits this ownership (bind mounts must be chowned to uid 10001).
RUN adduser -D -H -u 10001 passwd \
  && mkdir -p /data \
  && chown passwd:passwd /data
COPY --from=build /out/passwd-server /usr/local/bin/passwd-server
USER passwd
ENV PASSWD_ADDR=:8080 \
    PASSWD_ENV=production \
    PASSWD_DB=/data/passwd.db
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["passwd-server"]

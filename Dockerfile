FROM alpine:3.20
COPY zig-out/linux/bin/blockchain /app
ENTRYPOINT ["/app"]

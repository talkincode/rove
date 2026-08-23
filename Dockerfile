FROM rust:1.88-alpine AS builder

RUN apk add --no-cache build-base cmake perl

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
    && addgroup -S rove \
    && adduser -S -D -H -h /nonexistent -s /sbin/nologin -G rove rove

COPY --from=builder /app/target/release/rove /usr/local/bin/rove
COPY --from=builder /app/target/release/rove-hop /usr/local/bin/rove-hop
COPY --from=builder /app/target/release/rove-relay /usr/local/bin/rove-relay

USER rove
WORKDIR /app

ENTRYPOINT ["/usr/local/bin/rove"]
CMD ["--config", "/etc/rove/config.toml"]

FROM rust:1.70 as builder
WORKDIR /usr/src/app

COPY .. .

RUN cargo build --release

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/local/bin
COPY --from=builder /usr/src/app/target/release/llm_proxy .

CMD ["./llm_proxy"]
# Build stage
FROM rust:1.80-slim as builder

WORKDIR /app
COPY . .

RUN cargo build --release

# Run stage
FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /app/target/release/back /app/back

# Install nmap for the scanner engine
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

EXPOSE 3001

CMD ["./back"]

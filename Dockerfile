# Stage 1: Build Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/front
COPY front/package*.json ./
RUN npm install
COPY front/ ./
RUN npm run build

# Stage 2: Build Backend
FROM rust:1-slim-bookworm AS backend-builder
WORKDIR /app/back
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY back/Cargo.toml back/Cargo.lock ./
# Pre-build dependencies for caching
ENV SQLX_OFFLINE=true
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release
COPY back/src ./src
# Build for real
RUN touch src/main.rs && cargo build --release

# Stage 3: Final Runtime
FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y libssl3 ca-certificates curl nmap && rm -rf /var/lib/apt/lists/*
COPY --from=backend-builder /app/back/target/release/back ./path2root_api
COPY --from=frontend-builder /app/front/dist ./dist

# Env defaults
ENV DATABASE_URL=sqlite:///app/db.sqlite?mode=rwc
ENV JWT_SECRET=change_me_in_production
ENV PORT=3001

EXPOSE 3001
CMD ["./path2root_api"]

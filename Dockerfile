# SPDX-License-Identifier: LicenseRef-Propietario
# Static build (musl) → minimal scratch image. No network, no certs: the server
# calls out to nobody (that is the point). Result: a few MB, a single binary.

FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release --bin xue

FROM scratch
COPY --from=build /app/target/release/xue /xue
# MCP speaks over stdio; the client starts this binary and writes JSON-RPC to it.
ENTRYPOINT ["/xue"]

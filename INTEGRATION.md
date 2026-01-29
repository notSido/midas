# Integration Guide

## Docker Integration

### Multi-Stage Build

```dockerfile
FROM rust:latest as midas-builder
RUN apt-get update && apt-get install -y libclang-dev clang cmake
WORKDIR /build
RUN git clone https://github.com/notSido/midas.git
WORKDIR /build/midas
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=midas-builder /build/midas/target/release/themida-unpack /usr/local/bin/
RUN apt-get update && apt-get install -y libgcc-s1 && rm -rf /var/lib/apt/lists/*
```

### Usage

```bash
themida-unpack -i protected.exe -o unpacked.exe -v
```

## As a Library

```toml
[dependencies]
themida-unpack = { git = "https://github.com/notSido/midas.git" }
```

```rust
use themida_unpack::*;

fn main() -> Result<()> {
    let pe = pe::PeFile::load("protected.exe")?;
    let version = themida::detect_themida(&pe)?;
    println!("Detected: {:?}", version);
    Ok(())
}
```

## Requirements

- Linux (Debian/Ubuntu)
- Rust 1.70+
- libclang-dev, clang, cmake
- ~200MB disk space

## Building

```bash
cargo build --release
```

See README.md for detailed build instructions.

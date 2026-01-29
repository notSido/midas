# Integration Guide

## Quick Start (Docker)

Add to your Dockerfile:

```dockerfile
# Install midas unpacker
FROM rust:latest as midas-builder
RUN apt-get update && apt-get install -y libclang-dev cmake
WORKDIR /build
RUN git clone https://github.com/YOUR_USERNAME/midas.git
WORKDIR /build/midas
RUN cargo build --release

# Your main container
FROM debian:bookworm-slim
COPY --from=midas-builder /build/midas/target/release/themida-unpack /usr/local/bin/
RUN apt-get update && apt-get install -y libgcc-s1 && rm -rf /var/lib/apt/lists/*
```

## Usage in Your Container

```bash
# Unpack a Themida-protected binary
themida-unpack -i /path/to/protected.exe -o /path/to/unpacked.exe -v

# With custom instruction limit
themida-unpack -i protected.exe -o unpacked.exe --max-instructions 50000000
```

## As a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
themida-unpack = { git = "https://github.com/YOUR_USERNAME/midas.git" }
```

Use in your code:

```rust
use themida_unpack::*;

fn main() -> Result<()> {
    // Load PE
    let pe = pe::PeFile::load("protected.exe")?;
    
    // Detect Themida
    let version = themida::detect_themida(&pe)?;
    println!("Detected: {:?}", version);
    
    // TODO: Full unpacking (Phase 2-4)
    
    Ok(())
}
```

## Current Status

**Phase 1 Complete**: Foundation is ready
- PE parsing ✅
- Unicorn emulation wrapper ✅
- Windows structures ✅
- API hooks framework ✅

**Phases 2-4 Needed**: Full integration
- Complete emulation loop
- OEP detection integration
- IAT reconstruction
- PE dumping

Estimated: 55-85 hours to complete

## Testing

```bash
# Build in your Linux container
cd /path/to/midas
cargo build --release

# Run basic test (will show "not yet fully implemented")
./target/release/themida-unpack -i sample.exe -v
```

## Requirements

- Linux (Debian/Ubuntu recommended)
- Rust 1.70+
- libclang-dev, cmake
- ~200MB disk space for dependencies

## Support

See README.md, NOTES.md, and SUMMARY.md for detailed documentation.

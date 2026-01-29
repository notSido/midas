#!/bin/bash
# Test build script for midas in Docker

echo "=== Building midas in Docker container ==="

docker run --rm -v "$(pwd):/midas" -w /midas rust:latest bash -c '
  echo "Installing dependencies..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq libclang-dev clang cmake
  
  echo ""
  echo "Building project..."
  export LIBCLANG_PATH=/usr/lib/llvm-14/lib
  cargo build --release 2>&1 | grep -E "(Compiling|Finished|error)" || true
  
  if [ -f target/release/themida-unpack ]; then
    echo ""
    echo "✅ Build SUCCESS!"
    echo ""
    ls -lh target/release/themida-unpack
    echo ""
    echo "Testing binary..."
    target/release/themida-unpack --help
  else
    echo ""
    echo "❌ Build FAILED!"
    exit 1
  fi
'

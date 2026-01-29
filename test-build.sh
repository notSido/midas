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
  # Find the LLVM version available
  if [ -d /usr/lib/llvm-19/lib ]; then
    export LIBCLANG_PATH=/usr/lib/llvm-19/lib
  elif [ -d /usr/lib/llvm-18/lib ]; then
    export LIBCLANG_PATH=/usr/lib/llvm-18/lib
  elif [ -d /usr/lib/llvm-14/lib ]; then
    export LIBCLANG_PATH=/usr/lib/llvm-14/lib
  fi
  cargo build --release 2>&1 | grep -E "(Compiling|Finished|error|warning:)" || true
  
  if [ -f target/release/midas ]; then
    echo ""
    echo "✅ Build SUCCESS!"
    echo ""
    ls -lh target/release/midas
    echo ""
    echo "Testing binary..."
    target/release/midas --help
  else
    echo ""
    echo "❌ Build FAILED!"
    exit 1
  fi
'

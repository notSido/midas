#!/bin/bash
# Check build in Docker container

echo "=== Checking midas build in Docker ==="

docker run --rm -v "$(pwd):/midas" -w /midas rust:latest bash -c '
  echo "Installing dependencies..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq 2>&1 > /dev/null
  apt-get install -y -qq libclang-dev clang cmake 2>&1 > /dev/null
  
  echo ""
  echo "Finding libclang..."
  find /usr/lib -name "libclang.so*" 2>/dev/null || echo "Not found in /usr/lib"
  
  echo ""
  echo "Running cargo check..."
  # Try to find the correct LLVM version
  if [ -d /usr/lib/llvm-19/lib ]; then
    export LIBCLANG_PATH=/usr/lib/llvm-19/lib
  elif [ -d /usr/lib/llvm-18/lib ]; then
    export LIBCLANG_PATH=/usr/lib/llvm-18/lib
  elif [ -d /usr/lib/llvm-17/lib ]; then
    export LIBCLANG_PATH=/usr/lib/llvm-17/lib
  elif [ -d /usr/lib/llvm-14/lib ]; then
    export LIBCLANG_PATH=/usr/lib/llvm-14/lib
  fi
  echo "Using LIBCLANG_PATH: $LIBCLANG_PATH"
  
  cargo check --release 2>&1
'

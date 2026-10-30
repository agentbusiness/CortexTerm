#!/bin/sh
# Plugin build (run by cortex-pack in backend/): llama-server from the vendored llama.cpp with
# CMake (Metal on macOS, static, no tests/examples/web UI), then the Rust backend.
set -eu
cd "$(dirname "$0")"
here="$(pwd)"
build="$here/target/llama-build"
case "$(uname -s)" in
  Darwin) gpu="-DGGML_METAL=ON" ;;
  *) gpu="" ;;
esac
cmake -S "$here/vendor/llama.cpp" -B "$build" -DCMAKE_BUILD_TYPE=Release \
  $gpu -DGGML_NATIVE=OFF -DLLAMA_CURL=OFF -DLLAMA_OPENSSL=OFF -DBUILD_SHARED_LIBS=OFF \
  -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_APP=OFF \
  -DLLAMA_BUILD_TOOLS=ON -DLLAMA_BUILD_SERVER=ON -DLLAMA_BUILD_UI=OFF -DLLAMA_USE_PREBUILT_UI=OFF \
  -DLLAMA_BUILD_NUMBER=11876 -DLLAMA_BUILD_COMMIT=468ad58
jobs="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)"
cmake --build "$build" --config Release --target llama-server -j "$jobs"
mkdir -p "$here/target/release"
cp "$build/bin/llama-server" "$here/target/release/llama-server"
cargo build --release

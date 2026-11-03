#!/bin/sh
# Plugin build (run by cortex-pack in backend/): llama-server from the vendored llama.cpp with
# CMake, then the Rust backend. Everything llama-server needs lands in target/release/llama/.
#
# - macOS: Metal, one static executable.
# - Linux: the GPU backends as libraries llama-server loads at start (GGML_BACKEND_DL): CUDA (with
#   its runtime and cuBLAS beside it, so only NVIDIA's driver is needed), Vulkan (AMD, Intel and
#   NVIDIA through their drivers), and the CPU for what stays off the GPU (Haswell-class x86 and
#   ARMv8.2 with dotprod and fp16, and newer). A backend whose driver this machine lacks does not
#   load; a machine where none does runs no model. Built with Ninja.
set -eu
cd "$(dirname "$0")"
here="$(pwd)"
out="$here/target/release/llama"
case "$(uname -s)" in
  Darwin)
    build="$here/target/llama-build"
    gpu="-DGGML_METAL=ON -DGGML_METAL_EMBED_LIBRARY=ON -DBUILD_SHARED_LIBS=OFF"
    ;;
  *)
    build="$here/target/llama-ninja"
    gpu="-G Ninja -DGGML_CUDA=ON -DGGML_CUDA_NCCL=OFF -DGGML_VULKAN=ON -DBUILD_SHARED_LIBS=ON -DGGML_BACKEND_DL=ON \
      -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON -DCMAKE_INSTALL_RPATH=\$ORIGIN"
    case "$(uname -m)" in aarch64|arm64) gpu="$gpu -DGGML_CPU_ARM_ARCH=armv8.2-a+dotprod+fp16" ;; esac
    ;;
esac
cmake -S "$here/vendor/llama.cpp" -B "$build" -DCMAKE_BUILD_TYPE=Release \
  $gpu -DGGML_NATIVE=OFF -DGGML_OPENMP=OFF -DGGML_CCACHE=OFF -DLLAMA_CURL=OFF -DLLAMA_OPENSSL=OFF \
  -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_APP=OFF \
  -DLLAMA_BUILD_TOOLS=ON -DLLAMA_BUILD_SERVER=ON -DLLAMA_BUILD_UI=OFF -DLLAMA_USE_PREBUILT_UI=OFF \
  -DLLAMA_BUILD_NUMBER=11876 -DLLAMA_BUILD_COMMIT=468ad58
jobs="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)"
rm -rf "$out"
mkdir -p "$out"
case "$(uname -s)" in
  Darwin)
    cmake --build "$build" --config Release --target llama-server -j "$jobs"
    cp "$build/bin/llama-server" "$out/"
    ;;
  *)
    # The backends are their own targets (llama-server does not link them): build everything.
    cmake --build "$build" --config Release -j "$jobs"
    cp "$build/bin/llama-server" "$build"/bin/*.so "$out/"
    # The CUDA libraries under the names the backend loads them by (`lib….so.<major>`), once each.
    cuda="$(dirname "$(readlink -f "$(command -v nvcc)")")/../lib64"
    major="$(nvcc --version | sed -n 's/.*release \([0-9]*\)\..*/\1/p')"
    for lib in libcudart libcublas libcublasLt; do
      cp -L "$cuda/$lib.so.$major" "$out/"
    done
    ;;
esac
cargo build --release

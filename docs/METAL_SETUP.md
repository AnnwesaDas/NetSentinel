# Metal GPU path setup (Phase 4+)

The Metal compute path uses [metal-cpp](https://developer.apple.com/metal/cpp/),
Apple's official C++ bindings for Metal/Foundation/QuartzCore (Apache 2.0).
Apple publishes it at <https://github.com/apple/metal-cpp>, linked from
their metal-cpp page.

## One-time setup

From the repo root:

```sh
git clone --depth 1 https://github.com/apple/metal-cpp.git third_party/metal-cpp
```

That's all. The repo's top level is exactly the layout the build expects
(`Foundation/`, `Metal/`, `QuartzCore/`). `third_party/` is gitignored:
it's a local copy of Apple's SDK, not part of this project's source.

## Build with Metal enabled

```sh
cmake -S . -B build -DNETSENTINEL_ENABLE_METAL=ON
cmake --build build
```

If CMake can't find metal-cpp, it prints a `FATAL_ERROR` pointing back to
this file rather than failing with a confusing missing-header compiler
error. If your download landed somewhere else, point CMake at it directly:

```sh
cmake -S . -B build -DNETSENTINEL_ENABLE_METAL=ON -DMETAL_CPP_DIR=/path/to/metal-cpp
```

## First build: please report back exactly what happens

This code was written without access to a Mac. Every metal-cpp call in
`src/gpu/metal_context.cpp` has since been checked against the declarations
in Apple's actual headers, so the API usage is right. It still can't be
*compiled* off macOS, though, so **your build is the first real compile.** If it fails, paste the full
compiler error verbatim — line numbers and all — rather than a summary;
Metal/Objective-C++ error messages are usually precise about what's wrong,
and an exact error is the difference between a 30-second fix and guessing.

## Smoke test

Before anything else, run the vector-add smoke test — it validates the
device/queue/pipeline/buffer plumbing in isolation, deliberately separate
from the real anomaly-detection kernels so a plumbing bug and a math bug
are never debugged at the same time:

```sh
./build/metal_smoke_test
```

Expected output: it reports your GPU's name and `PASS` after verifying
1024 GPU-computed sums against CPU-computed expected values. Anything
else — a crash, a `FAIL`, wrong values — means something in the
device/pipeline setup is off, and is worth debugging before touching the
real kernels.

## Entropy kernel check

`shaders/payload_entropy.metal` computes Shannon entropy for a batch of
payloads, one threadgroup per payload. The test runs ~2,000 payloads
(edge cases, random data up to 65,535 bytes, a realistic mixed batch)
through both it and the CPU implementation and compares:

```sh
./build/tests/test_gpu_entropy
```

It passes when every value agrees within 1e-4 and the high-entropy alert
decision is the same on both paths for every payload. It also runs as part
of `ctest` in a Metal-enabled build.

## Running the detector on the GPU

```sh
./build/netsentinel -r capture.pcap -g
```

The startup line names the backend (`entropy on gpu (Apple M5)`). Alerts
should match a run without `-g` on the same file. If a line saying batches
"fell back to CPU entropy" appears at the end, some GPU dispatches failed;
report it along with the full output.

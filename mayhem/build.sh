#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

TARGETS="fuzz_snp_data fuzz_udp_listen fuzz_p2p_signal fuzz_identity_cert"
LIB_DEFS="-DSTEAMNETWORKINGSOCKETS_FOREXPORT -DENABLE_OPENSSLCONNECTION -DGOOGLE_PROTOBUF_NO_RTTI -DLINUX -DSTEAMNETWORKINGSOCKETS_ENABLE_ICE -DVALVE_CRYPTO_25519_OPENSSLEVP -DVALVE_CRYPTO_ENABLE_25519 -DVALVE_CRYPTO_OPENSSL"
LIBS="-lprotobuf -lssl -lcrypto -lpthread"
# No -DCMAKE_C_COMPILER: re-running with a different compiler path than the cached one (ccache prefill
# wrapper vs plain clang) makes cmake drop its cache and silently lose -DBUILD_TESTS=ON. CC/CXX env is used.
CMAKE_COMMON="-G Ninja -DBUILD_STATIC_LIB=ON -DBUILD_SHARED_LIB=OFF -DBUILD_EXAMPLES=OFF -DUSE_CRYPTO=OpenSSL"

# 1) Test suite with the project's normal flags (Debug, so the suites' assert()s are live), built first.
#    Plus a small known-answer probe linked against that same normal-flags library.
cmake -S . -B build-tests $CMAKE_COMMON -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON \
      -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
      -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS"
cmake --build build-tests --target test_crypto test_connection -j"$MAYHEM_JOBS"
$CXX -std=gnu++17 -O1 $COVERAGE_FLAGS $LIB_DEFS \
     -I"$SRC/include" -I"$SRC/src/common" -I"$SRC/src/public" -I"$SRC/build-tests/src" \
     -I"$SRC/src/steamnetworkingsockets" -I"$SRC/src/steamnetworkingsockets/clientlib" \
     mayhem/kat_probe.cpp build-tests/src/libGameNetworkingSockets_s.a $LIBS \
     -o build-tests/bin/kat_probe

# 2) The library itself, sanitized, with DWARF 3. UBSan checks relaxed for benign patterns that would
#    otherwise halt on trivial inputs and mask everything deeper (ASan and all other UBSan checks stay on):
#    alignment (snp.cpp reads packed wire fields through casts), nonnull-attribute (memcpy(NULL, p, 0) for
#    zero-length messages), enum (CSteamID universe loaded as an out-of-range EUniverse). The explicit
#    -O2 -DNDEBUG flags for RelWithDebInfo replace cmake's default -g (DWARF 5).
UBSAN_RELAX="-fno-sanitize=alignment,nonnull-attribute,enum"
FUZZ_CXXFLAGS="$SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
cmake -S . -B build-fuzz $CMAKE_COMMON -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTS=OFF \
      -DCMAKE_C_FLAGS="$FUZZ_CXXFLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_CXXFLAGS" \
      -DCMAKE_C_FLAGS_RELWITHDEBINFO="-O2 -DNDEBUG" -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O2 -DNDEBUG"
cmake --build build-fuzz --target GameNetworkingSockets_s -j"$MAYHEM_JOBS"
FUZZ_LIB="$SRC/build-fuzz/src/libGameNetworkingSockets_s.a"

# 3) Harnesses: libFuzzer binaries + standalone (run-once) reproducers.
HARNESS_FLAGS="-O2 -DNDEBUG -std=gnu++17 -fno-exceptions -fno-rtti $LIB_DEFS $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS"
HARNESS_INC="-I$SRC/include -I$SRC/src/common -I$SRC/src/public -I$SRC/build-fuzz/src -I$SRC/src/steamnetworkingsockets -I$SRC/src/steamnetworkingsockets/clientlib -I$SRC/mayhem"
mkdir -p build-fuzz/harness
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build-fuzz/harness/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build-fuzz/harness/standalone_main.o
for t in $TARGETS; do
  $CXX $HARNESS_FLAGS $HARNESS_INC -c mayhem/$t.cpp -o build-fuzz/harness/$t.o
  $CXX $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
       build-fuzz/harness/$t.o build-fuzz/harness/lsan_off.o "$FUZZ_LIB" $LIBS -o "/mayhem/$t"
  $CXX $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS \
       build-fuzz/harness/$t.o build-fuzz/harness/standalone_main.o build-fuzz/harness/lsan_off.o \
       "$FUZZ_LIB" $LIBS -o "/mayhem/$t-standalone"
done

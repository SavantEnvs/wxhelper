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

# wxhelper itself is a Windows-only DLL (MSVC/MASM, Detours, WeChatWin.dll offsets); its root
# CMakeLists.txt cannot run on Linux. The code that parses untrusted bytes is the portable
# vendored libraries it ships in src/ — mongoose.c (HTTP/WebSocket server, DNS, MQTT), lz4.c,
# tinyxml2.cpp and base64.cpp — so those are built here, sanitized, exactly as the DLL builds them.
B="$SRC/mayhem/build"          # gitignored (mayhem/.gitignore)
H="$SRC/mayhem/harnesses"
mkdir -p "$B/fuzz" "$B/test" "$B/b64"
# src/base64.cpp starts with `#include "pch.h"` (Windows.h + Detours). A quoted include is looked up
# beside the source first, so compile a fresh copy next to an empty pch.h (re-copied every run, so
# an edit to src/base64.cpp is always picked up).
cp "$SRC/src/base64.cpp" "$B/b64/base64.cpp"
: > "$B/b64/pch.h"

# -fsanitize=fuzzer-no-link: SanCov on the project objects too (unconditional, also with no sanitizers)
FUZZ_C="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link"
INC="-I$SRC/src"

# 1) project sources, sanitized
$CC  $FUZZ_C $INC -c "$SRC/src/mongoose.c"   -o "$B/fuzz/mongoose.o"
$CC  $FUZZ_C $INC -c "$SRC/src/lz4.c"        -o "$B/fuzz/lz4.o"
$CXX $FUZZ_C $INC -std=c++17 -c "$SRC/src/tinyxml2.cpp" -o "$B/fuzz/tinyxml2.o"
$CXX $FUZZ_C $INC -std=c++17 -c "$B/b64/base64.cpp"     -o "$B/fuzz/base64.o"
$CXX $FUZZ_C -c "$SRC/mayhem/lsan_off.cc" -o "$B/fuzz/lsan_off.o"
$CC  $FUZZ_C -c "$STANDALONE_FUZZ_MAIN" -o "$B/fuzz/standalone_main.o"

# 2) harnesses: libFuzzer binary + run-once standalone reproducer each
link() {  # link <name> <objs...>
  local name="$1"; shift
  $CXX $FUZZ_C $LIB_FUZZING_ENGINE "$B/fuzz/$name.o" "$@" "$B/fuzz/lsan_off.o" -o "$B/$name"
  $CXX $FUZZ_C "$B/fuzz/standalone_main.o" "$B/fuzz/$name.o" "$@" "$B/fuzz/lsan_off.o" -o "$B/$name-standalone"
}
for h in fuzz_mqtt fuzz_http fuzz_dns fuzz_url fuzz_ws_server; do
  $CC $FUZZ_C $INC -c "$H/$h.c" -o "$B/fuzz/$h.o"
  link "$h" "$B/fuzz/mongoose.o"
done
$CXX $FUZZ_C $INC -std=c++17 -c "$H/fuzz_xml.cpp"     -o "$B/fuzz/fuzz_xml.o"
link fuzz_xml "$B/fuzz/tinyxml2.o"
$CXX $FUZZ_C $INC -std=c++17 -c "$H/fuzz_lz4_xml.cpp" -o "$B/fuzz/fuzz_lz4_xml.o"
link fuzz_lz4_xml "$B/fuzz/lz4.o" "$B/fuzz/tinyxml2.o"
$CXX $FUZZ_C $INC -std=c++17 -c "$H/fuzz_base64.cpp"  -o "$B/fuzz/fuzz_base64.o"
link fuzz_base64 "$B/fuzz/base64.o"

# 3) functional self-test (upstream has no tests): known-answer checks over the same sources,
#    NORMAL flags, no sanitizers. test.sh only runs it.
T="-O1 $COVERAGE_FLAGS"
$CC  $T $INC -c "$SRC/src/mongoose.c" -o "$B/test/mongoose.o"
$CC  $T $INC -c "$SRC/src/lz4.c"      -o "$B/test/lz4.o"
$CXX $T $INC -std=c++17 -c "$SRC/src/tinyxml2.cpp" -o "$B/test/tinyxml2.o"
$CXX $T $INC -std=c++17 -c "$B/b64/base64.cpp"     -o "$B/test/base64.o"
$CXX $T $INC -std=c++17 "$SRC/mayhem/selftest.cpp" "$B/test/mongoose.o" "$B/test/lz4.o" \
    "$B/test/tinyxml2.o" "$B/test/base64.o" -o "$B/selftest"
echo "build.sh: done"

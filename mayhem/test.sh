#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# mayhem/selftest (built by build.sh) runs known-answer checks over wxhelper's vendored parsers
# (base64, LZ4, tinyxml2, mongoose HTTP/MQTT/DNS/URL) and prints PASS/FAIL per check. Every
# expected check must be reported as PASS; a missing line counts as a failure.
BIN="$SRC/mayhem/build/selftest"
[ -x "$BIN" ] || { echo "test.sh: $BIN missing — run mayhem/build.sh" >&2; emit_ctrf selftest 0 1; exit 1; }
EXPECTED="base64_encode base64_decode base64_url base64_reject lz4_roundtrip lz4_reject xml_title
xml_attr xml_reject http_parse http_match_uri http_header http_query_var http_incomplete mqtt_parse
mqtt_prop_varint mqtt_incomplete url_host url_port url_user_pass url_uri aton_ipv4 aton_reject dns_parse"
out="$("$BIN" 2>&1)"; rc=$?
echo "$out"
passed=0; failed=0
for t in $EXPECTED; do
  if grep -qx "PASS $t" <<<"$out"; then passed=$((passed+1)); else echo "FAILED: $t"; failed=$((failed+1)); fi
done
[ "$rc" -eq 0 ] || { echo "selftest exited $rc"; failed=$((failed+1)); }
emit_ctrf selftest "$passed" "$failed" 0

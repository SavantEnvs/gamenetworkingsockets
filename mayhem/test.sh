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

BIN="$SRC/build-tests/bin"
PASSED=0 ; FAILED=0

# Run <name> <required-marker-regex> <timeout> <cmd...>: rc must be 0 AND the marker must appear in the
# output. A missing binary is a failure, never a skip.
run_check() {
  local name="$1" marker="$2" tmo="$3" ; shift 3
  local out rc
  if [ ! -x "$1" ]; then echo "FAIL $name: missing binary $1 (build.sh bug)"; FAILED=$((FAILED+1)); return; fi
  out=$(cd "$BIN" && timeout "$tmo" "$@" 2>&1) ; rc=$?
  if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -Eq "$marker"; then
    echo "PASS $name"; PASSED=$((PASSED+1))
  else
    echo "FAIL $name (rc=$rc)"; printf '%s\n' "$out" | tail -n 15; FAILED=$((FAILED+1))
  fi
}

# Crypto known-answer suite: asserts (Debug build, so live) on AES-GCM/SHA/HMAC/curve25519 vectors, then benchmarks.
run_check test_crypto 'Symmetric GCM decrypt \(big\):.*MB/sec' 600 "$BIN/test_crypto"

# Connection suites: each asserts payload delivery/ordering/queue semantics over real loopback connections.
for t in identity pipe lane_quick_queueanddrain send_buffer_full recv_buf_full; do
  run_check "test_connection:$t" "Test '$t' completed OK" 300 "$BIN/test_connection" "$t"
done

# Known-answer probe: SHA-256/HMAC-SHA-256 vectors, identity/IP parse+render round trips, pipe payload round trip.
probe_out=$( (cd "$BIN" && timeout 120 ./kat_probe 2>&1) ) ; probe_rc=$?
echo "$probe_out"
if [ ! -x "$BIN/kat_probe" ]; then echo "FAIL kat_probe: missing binary"; FAILED=$((FAILED+1)); else
  for p in sha256_abc hmac_sha256_rfc4231_1 identity_ip identity_str identity_steamid identity_reject \
           ip_v6 ip_v4_default_port ip_reject pipe_create pipe_send pipe_payload_roundtrip; do
    if [ "$probe_rc" -eq 0 ] && printf '%s\n' "$probe_out" | grep -q "^PROBE $p OK$"; then
      PASSED=$((PASSED+1))
    else
      echo "FAIL kat_probe:$p"; FAILED=$((FAILED+1))
    fi
  done
fi

emit_ctrf "gns-oracle" "$PASSED" "$FAILED" 0

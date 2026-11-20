#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer suite for libpeconv (upstream's own tests are Windows programs
# that run PE images, so they cannot run here). For each sample PE in mayhem/test/, the self test
# (built by build.sh with normal flags) loads it with libpeconv and prints headers, relocation and
# import validity, thunk count, export names and the unmapped size; the output must match the
# committed golden file mayhem/test/expected/<sample>.txt exactly.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
cd "$SRC"

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

RUNNER="$SRC/mayhem/out/peconv_selftest"
if [ ! -x "$RUNNER" ]; then
  echo "missing $RUNNER — run mayhem/build.sh first" >&2
  emit_ctrf "peconv-known-answer" 0 1
  exit 1
fi

passed=0; failed=0
for sample in mayhem/test/*.dll; do
  name=$(basename "$sample")
  expected="mayhem/test/expected/$name.txt"
  if actual=$("$RUNNER" "$sample") && diff -u "$expected" <(printf '%s\n' "$actual"); then
    echo "PASS $name"; passed=$((passed + 1))
  else
    echo "FAIL $name"; failed=$((failed + 1))
  fi
done
emit_ctrf "peconv-known-answer" "$passed" "$failed"

#!/usr/bin/env bash
#
# mayhem/build.sh — libpeconv fuzz harnesses + known-answer self test.
#
# libpeconv is a Windows library (every source includes <windows.h>). It is built natively for
# Linux against Wine's Windows headers (headers only, cached at $WINE_INC by the Dockerfile; no
# Wine runtime), with mayhem/harnesses/win_stubs.cpp standing in for the few kernel32 calls it
# makes. Wine's headers keep DWORD/LONG 32-bit on LP64, so PE structure layouts are exact.
# Three sources need the Windows kernel/ntdll internals and are not built: exceptions_parser.cpp,
# peb_lookup.cpp (live process PEB/ntdll) and hooks.cpp (live-code patching).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${WINE_INC:=/opt/toolchains/deps/wine-10.0/include}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
[ -f "$WINE_INC/windows.h" ] || { echo "missing Wine headers at $WINE_INC" >&2; exit 1; }

# Wine-header build flags: wchar_t must be 16-bit like Windows; NOMINMAX keeps std::min/max usable;
# _WIN32_WINNT=0x0A00 makes winnt.h define IMAGE_DELAYLOAD_DESCRIPTOR (libpeconv's own copy is
# guarded by it). Wine's headers are noisy under clang, so their warnings are silenced.
WINFLAGS="-fshort-wchar -DNOMINMAX -D_WIN32_WINNT=0x0A00 -DLOG_VERBOSITY=0 -isystem $WINE_INC -I$SRC/libpeconv/include -I$SRC/mayhem/harnesses -Wno-everything"
SOURCES=()
for f in libpeconv/src/*.cpp; do
  case "$(basename "$f")" in exceptions_parser.cpp|peb_lookup.cpp|hooks.cpp) continue ;; esac
  SOURCES+=("$f")
done

# UBSan's `alignment` check is relaxed (only that check; ASan and the rest of UBSan stay halting):
# PE parsing reads header/thunk/relocation fields at whatever offset the file puts them, as the
# Windows loader does, and every target trips it on its first input otherwise. Misaligned loads
# are well defined on x86. Applied only when sanitizers are on.
[ -n "$SANITIZER_FLAGS" ] && SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=alignment"

B="$SRC/mayhem/build"   # gitignored (mayhem/.gitignore)
OUT="$SRC/mayhem/out"   # gitignored; fuzz + standalone binaries

# build_lib <dir> <flags...>: libpeconv + the Win32 stubs into <dir>/libpeconv.a
build_lib() {
  local dir="$1"; shift
  mkdir -p "$dir"
  printf '%s\n' "${SOURCES[@]}" mayhem/harnesses/win_stubs.cpp | \
    xargs -P "$MAYHEM_JOBS" -I{} sh -c 'o="$1/$(basename "$2" .cpp).o"; shift 2; exec '"$CXX"' "$@" -c "$0" -o "$o"' {} "$dir" {} $WINFLAGS "$@"
  rm -f "$dir/libpeconv.a"
  ar rcs "$dir/libpeconv.a" "$dir"/*.o
}

# 1) Sanitized + DWARF-3 library (the fuzzed code is instrumented, not only the harness).
# shellcheck disable=SC2086
build_lib "$B/fuzz" $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1

# 2) Each harness twice: libFuzzer binary and run-once standalone reproducer.
mkdir -p "$OUT"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
# shellcheck disable=SC2086
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$B/lsan_off.o"
HARNESSES="fuzz_load_pe fuzz_dump_pe fuzz_imports fuzz_data_dirs fuzz_exports fuzz_fix_imports"
for h in $HARNESSES; do
  # shellcheck disable=SC2086
  $CXX $WINFLAGS $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 -c "mayhem/harnesses/$h.cpp" -o "$B/$h.o"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$h.o" "$B/lsan_off.o" "$B/fuzz/libpeconv.a" -o "$OUT/$h"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/standalone_main.o" "$B/$h.o" "$B/lsan_off.o" "$B/fuzz/libpeconv.a" -o "$OUT/$h-standalone"
done

# 3) Known-answer self test with normal flags (no sanitizers), run by mayhem/test.sh.
# shellcheck disable=SC2086
build_lib "$B/test" -O2 $COVERAGE_FLAGS
# shellcheck disable=SC2086
$CXX $WINFLAGS -O2 $COVERAGE_FLAGS mayhem/harnesses/peconv_selftest.cpp "$B/test/libpeconv.a" -o "$OUT/peconv_selftest"
echo "built: $HARNESSES peconv_selftest -> $OUT"

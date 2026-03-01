#!/bin/bash
# CKB-ESP32 host test runner
# Usage: bash test/run_tests.sh [--md] [--verbose]

set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO"

MD=0; VERBOSE=0
for arg in "$@"; do
  [[ "$arg" == "--md" ]]      && MD=1
  [[ "$arg" == "--verbose" ]] && VERBOSE=1
done

# Colours
R='\033[0;31m' G='\033[0;32m' Y='\033[0;33m' B='\033[0;34m' C='\033[0;36m' NC='\033[0m' BOLD='\033[1m'

# Build trezor C objects once
build_c_objects() {
  gcc -std=c11 -w -c src/trezor_crypto/secp256k1.c -Isrc/trezor_crypto -Isrc -o test/secp256k1.o 2>/dev/null
  gcc -std=c11 -w -c src/trezor_crypto/memzero.c   -Isrc/trezor_crypto          -o test/memzero.o   2>/dev/null
  gcc -std=c11 -w -c src/trezor_crypto/sha3.c       -Isrc/trezor_crypto          -o test/sha3.o      2>/dev/null
}

TREZOR_SRCS="src/trezor_crypto/bignum.c src/trezor_crypto/ecdsa.c \
  src/trezor_crypto/hasher.c src/trezor_crypto/hmac.c \
  src/trezor_crypto/rand.c src/trezor_crypto/rfc6979.c \
  src/trezor_crypto/sha2.c src/trezor_crypto/ripemd160.c"
TREZOR_OBJS="test/secp256k1.o test/memzero.o test/sha3.o"
CXX_FLAGS="-DHOST_TEST -std=c++17 -w -Isrc -Isrc/blake2b -Isrc/trezor_crypto -Ithird_party/ArduinoJson/src"
BLAKE="src/blake2b/blake2b.c"

declare -A SUITE_PASS SUITE_FAIL SUITE_TIME SUITE_OUT SUITE_NAMES

run_suite() {
  local name="$1" bin="$2"; shift 2
  local build_cmd=("$@")
  SUITE_NAMES[$name]="$name"
  local t0=$SECONDS
  local build_out; build_out=$(g++ "${build_cmd[@]}" -o "$bin" 2>&1) || {
    SUITE_PASS[$name]=0; SUITE_FAIL[$name]=1; SUITE_TIME[$name]=0
    SUITE_OUT[$name]="BUILD FAILED:\n$build_out"
    return
  }
  local out; out=$(timeout 120 "$bin" 2>&1) || true
  SUITE_TIME[$name]=$((SECONDS - t0))
  local pass fail
  pass=$(echo "$out" | grep -cE '^\s*PASS:' 2>/dev/null || true)
  fail=$(echo "$out" | grep -cE '^\s*FAIL:' 2>/dev/null || true)
  SUITE_PASS[$name]=$pass
  SUITE_FAIL[$name]=$fail
  SUITE_OUT[$name]="$out"
}

echo ""
printf "${BOLD}${C}╔══════════════════════════════════════════════════╗${NC}\n"
printf "${BOLD}${C}║          CKB-ESP32 Host Test Suite               ║${NC}\n"
printf "${BOLD}${C}║  g++ $(g++ --version | head -1 | grep -oP '\d+\.\d+\.\d+')  •  aarch64  •  $(date +%Y-%m-%d)           ║${NC}\n"
printf "${BOLD}${C}╚══════════════════════════════════════════════════╝${NC}\n"
echo ""
echo "  Building C objects..."
build_c_objects

run_suite "blake2b" test/test_blake2b \
  $CXX_FLAGS test/test_blake2b.cpp $BLAKE

run_suite "molecule" test/test_molecule \
  $CXX_FLAGS test/test_molecule.cpp $BLAKE

run_suite "bip39" test/test_bip39 \
  $CXX_FLAGS test/test_bip39.cpp $BLAKE $TREZOR_SRCS $TREZOR_OBJS -lm

run_suite "signer" test/test_signer \
  $CXX_FLAGS -DCKB_WITH_SIGNER test/test_signer.cpp \
  src/CKBSigner.cpp $BLAKE $TREZOR_SRCS $TREZOR_OBJS -lm

run_suite "client_static" test/test_client_static \
  $CXX_FLAGS -DCKB_NODE_FULL test/test_client_static.cpp \
  src/CKB.cpp $BLAKE $TREZOR_SRCS $TREZOR_OBJS -lm

# Print per-suite results
for name in blake2b molecule bip39 signer client_static; do
  p=${SUITE_PASS[$name]}; f=${SUITE_FAIL[$name]}; t=${SUITE_TIME[$name]}
  if [[ $f -eq 0 && $p -gt 0 ]]; then
    printf "  ${G}✓${NC} %-20s ${BOLD}%3d tests${NC}  (${t}s)\n" "$name" "$p"
  else
    printf "  ${R}✗${NC} %-20s ${BOLD}%3d passed, %d failed${NC}  (${t}s)\n" "$name" "$p" "$f"
  fi
  if [[ $VERBOSE -eq 1 ]]; then echo "${SUITE_OUT[$name]}"; fi
done

# Summary
TOTAL_P=0; TOTAL_F=0; TOTAL_T=0
for name in blake2b molecule bip39 signer client_static; do
  TOTAL_P=$((TOTAL_P + SUITE_PASS[$name]))
  TOTAL_F=$((TOTAL_F + SUITE_FAIL[$name]))
  TOTAL_T=$((TOTAL_T + SUITE_TIME[$name]))
done

echo ""
printf "  ${BOLD}┌─────────────────────────┬────────┬────────┬──────┐${NC}\n"
printf "  ${BOLD}│ Suite                   │ Passed │ Failed │  (s) │${NC}\n"
printf "  ${BOLD}├─────────────────────────┼────────┼────────┼──────┤${NC}\n"
for name in blake2b molecule bip39 signer client_static; do
  p=${SUITE_PASS[$name]}; f=${SUITE_FAIL[$name]}; t=${SUITE_TIME[$name]}
  [[ $f -eq 0 ]] && col=$G || col=$R
  printf "  │ ${col}%-23s${NC} │ %6d │ %6d │ %4d │\n" "$name" "$p" "$f" "$t"
done
printf "  ${BOLD}├─────────────────────────┼────────┼────────┼──────┤${NC}\n"
[[ $TOTAL_F -eq 0 ]] && col=$G || col=$R
printf "  ${BOLD}│ ${col}%-23s${NC}${BOLD} │ %6d │ %6d │ %4d │${NC}\n" "TOTAL" "$TOTAL_P" "$TOTAL_F" "$TOTAL_T"
printf "  ${BOLD}└─────────────────────────┴────────┴────────┴──────┘${NC}\n"
echo ""

# Failing test details
for name in blake2b molecule bip39 signer client_static; do
  if [[ ${SUITE_FAIL[$name]} -gt 0 ]]; then
    echo "  ${R}Failures in $name:${NC}"
    echo "${SUITE_OUT[$name]}" | grep -E '^\s*FAIL:' | while read l; do
      echo "    $l"
    done
  fi
done

# --md report
if [[ $MD -eq 1 ]]; then
  COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
  REPORT="test/REPORT.md"
  {
    echo "# CKB-ESP32 Host Test Report"
    echo ""
    echo "**Date:** $(date '+%Y-%m-%d %H:%M')  |  **Commit:** \`$COMMIT\`  |  **Platform:** aarch64 Linux  |  **Compiler:** g++ $(g++ --version | head -1 | grep -oP '\d+\.\d+\.\d+')"
    echo ""
    echo "## Summary"
    echo ""
    echo "| Suite | Passed | Failed | Time |"
    echo "|-------|--------|--------|------|"
    for name in blake2b molecule bip39 signer client_static; do
      [[ ${SUITE_FAIL[$name]} -eq 0 ]] && icon="🟢" || icon="🔴"
      echo "| $icon $name | ${SUITE_PASS[$name]} | ${SUITE_FAIL[$name]} | ${SUITE_TIME[$name]}s |"
    done
    echo "| **Total** | **$TOTAL_P** | **$TOTAL_F** | ${TOTAL_T}s |"
    echo ""
    echo "## Test Cases"
    echo ""
    for name in blake2b molecule bip39 signer client_static; do
      echo "### $name"
      echo ""
      echo "<details><summary>$([ ${SUITE_FAIL[$name]} -eq 0 ] && echo "✅" || echo "❌") ${SUITE_PASS[$name]} passed, ${SUITE_FAIL[$name]} failed</summary>"
      echo ""
      echo '```'
      echo "${SUITE_OUT[$name]}" | grep -E '^\s*(PASS|FAIL):' | sed 's/^[[:space:]]*//'
      echo '```'
      echo ""
      echo "</details>"
      echo ""
    done
  } > "$REPORT"
  echo "  Report saved → $REPORT"
fi

[[ $TOTAL_F -eq 0 ]] && exit 0 || exit 1

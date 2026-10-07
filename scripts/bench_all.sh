#!/usr/bin/env bash
# Runs the DPF benchmarks (Floram, HT, HT-mal with IKNP/KOS and with Ferret,
# Floram-arith, FssNN, Duoram 2P/3P) over the same sweep and writes one CSV
# per protocol into results/.
#
#   scripts/bench_all.sh [--max-in-bits n] [--reps R] [--points P] [mode]
#
# mode is gen|eval|full|all (default all). Floram, HT and HT-mal sweep
# out-bits over 127,128,256,512; Floram-arith and Duoram over 16,32,64 (their
# ring Z_2^l is at most 64 bits); FssNN only has 1 (its output group is Z2).
# 127 is where HT uses the PRG-free Convert.
set -euo pipefail
cd "$(dirname "$0")/.."

MODE=all
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    gen|eval|full|all) MODE="$1"; shift ;;
    --max-in-bits|--reps|--points) ARGS+=("$1" "$2"); shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 1 ;;
  esac
done
[[ " ${ARGS[*]-} " == *" --max-in-bits "* ]] || ARGS+=(--max-in-bits 20)

mkdir -p results
cargo build --release -p floram-cprg -p half-tree -p floram-arith -p fssnn -p duoram --examples

BIN=target/release/examples
echo "floram"       && "$BIN/bench"              "$MODE" --sweep --out-list 127,128,256,512 "${ARGS[@]}"                 | tee results/floram.csv
echo "ht"           && "$BIN/bench-half-tree"    "$MODE" --sweep --out-list 127,128,256,512 --variant ht "${ARGS[@]}"    | tee results/ht.csv
echo "ht-mal"       && "$BIN/bench-half-tree"    "$MODE" --sweep --out-list 128,256,512 --variant mal "${ARGS[@]}"       | tee results/ht-mal.csv
echo "ht-mal-ferret" && "$BIN/bench-half-tree"   "$MODE" --sweep --out-list 128,256,512 --variant mal-ferret "${ARGS[@]}" | tee results/ht-mal-ferret.csv
echo "floram-arith" && "$BIN/bench-floram-arith" "$MODE" --sweep --out-list 16,32,64 "${ARGS[@]}"                        | tee results/floram-arith.csv
echo "fssnn"        && "$BIN/bench-fssnn"        "$MODE" --sweep --out-list 1 "${ARGS[@]}"                               | tee results/fssnn.csv
echo "duoram-2p"    && "$BIN/bench-duoram"       "$MODE" --sweep --out-list 16,32,64 --variant 2p "${ARGS[@]}"           | tee results/duoram-2p.csv
echo "duoram-3p"    && "$BIN/bench-duoram"       "$MODE" --sweep --out-list 16,32,64 --variant 3p "${ARGS[@]}"           | tee results/duoram-3p.csv

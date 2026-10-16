#!/usr/bin/env bash
# Runs the DPF benchmarks (Floram, HT, HT-mal with IKNP/KOS and with Ferret,
# Floram-arith, FssNN bin/arith, Duoram 2P/3P) over the same sweep and writes one CSV
# per protocol into results/.
#
#   [OUT_LIST=a,b,..] scripts/bench_all.sh [--max-in-bits n] [--reps R] [--points P] [--stream [--batch-log b]] [mode]
#
# mode is gen|eval|full|all (default all). Every protocol sweeps out-bits over
# OUT_LIST (default 64,128), so each output width has all protocols side by
# side. Floram-arith and Duoram run Z_2^l on 64-bit words for l <= 64 and on
# 128-bit words above; at l = 128 every protocol takes one more PRG call per
# leaf for the output, since a 128-bit leaf has only 127 bits above its t-bit.
#
# --stream runs every protocol with the streaming tree (dpf_common::stream):
# memory O(batch·n) instead of a few × 2^n blocks, about 2× the Gen compute,
# identical messages and rounds. The CSVs then go to results/<name>-stream.csv.
set -euo pipefail
cd "$(dirname "$0")/.."

MODE=all
OUT_LIST=${OUT_LIST:-64,128}
ARGS=()
SUFFIX=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    gen|eval|full|all) MODE="$1"; shift ;;
    --max-in-bits|--reps|--points|--batch-log) ARGS+=("$1" "$2"); shift 2 ;;
    --stream) ARGS+=("$1"); SUFFIX=-stream; shift ;;
    *) echo "unknown argument $1" >&2; exit 1 ;;
  esac
done
[[ " ${ARGS[*]-} " == *" --max-in-bits "* ]] || ARGS+=(--max-in-bits 20)

mkdir -p results
cargo build --release -p floram-cprg -p half-tree -p floram-arith -p fssnn -p duoram --examples

BIN=target/release/examples
echo "floram"       && "$BIN/bench"              "$MODE" --sweep --out-list "$OUT_LIST" "${ARGS[@]}"                 | tee results/floram$SUFFIX.csv
echo "ht"           && "$BIN/bench-half-tree"    "$MODE" --sweep --out-list "$OUT_LIST" --variant ht "${ARGS[@]}"    | tee results/ht$SUFFIX.csv
echo "ht-mal-ferret" && "$BIN/bench-half-tree"   "$MODE" --sweep --out-list "$OUT_LIST" --variant mal-ferret "${ARGS[@]}" | tee results/ht-mal-ferret$SUFFIX.csv
echo "floram-arith" && "$BIN/bench-floram-arith" "$MODE" --sweep --out-list "$OUT_LIST" "${ARGS[@]}"                        | tee results/floram-arith$SUFFIX.csv
echo "fssnn-bin"    && "$BIN/bench-fssnn"        "$MODE" --sweep --out-list "$OUT_LIST" --variant bin "${ARGS[@]}"  | tee results/fssnn-bin$SUFFIX.csv
echo "fssnn-arith"  && "$BIN/bench-fssnn"        "$MODE" --sweep --out-list "$OUT_LIST" --variant arith "${ARGS[@]}" | tee results/fssnn-arith$SUFFIX.csv
echo "duoram-2p"    && "$BIN/bench-duoram"       "$MODE" --sweep --out-list "$OUT_LIST" --variant 2p "${ARGS[@]}"           | tee results/duoram-2p$SUFFIX.csv
echo "duoram-3p"    && "$BIN/bench-duoram"       "$MODE" --sweep --out-list "$OUT_LIST" --variant 3p "${ARGS[@]}"           | tee results/duoram-3p$SUFFIX.csv

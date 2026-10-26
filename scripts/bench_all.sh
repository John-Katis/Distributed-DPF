#!/usr/bin/env bash
# Runs the DPF benchmarks (Floram, HT, HT-mal with Ferret, Floram-arith,
# FssNN bin/arith, Duoram 2P/3P, ours: ht-aes sh/mal/mal-auth) over the same sweep and writes one CSV per
# protocol into results-gen/ (mode gen) or results-eval/ (eval, full, all).
#
#   [OUT_LIST=a,b,..] scripts/bench_all.sh [--max-in-bits n] [--reps R] [--points P] [--batch-log b] [mode]
#
# mode is gen|eval|full|all (default gen). The sweep covers in-bits 8..=32
# (--max-in-bits) and out-bits OUT_LIST (default 64,128), so each output
# width has all protocols side by side. Floram-arith and Duoram run Z_2^l on
# 64-bit words for l <= 64 and on 128-bit words above; at l = 128 every
# protocol takes one more PRG call per leaf for the output, since a 128-bit
# leaf has only 127 bits above its t-bit.
#
# The tree-based protocols use the stored tree as long as it fits in memory
# and switch to the streaming tree (dpf_common::stream, ~2× the Gen compute,
# identical messages and rounds; variant `+stream` in the CSV) from the
# in-bits below. The cut-offs are for ~26 GB free RAM, from Gen's peak RSS at
# n = 22, 24 (2× per input bit): ~64 B·2^n for Floram, HT and Floram-arith,
# ~160 B·2^n for HT-mal, ~32 B·2^n for Duoram. FssNN's Gen only follows the
# path to alpha (flat ~1 GB), so it always runs stored; so does ht-aes (ours). Their full-domain
# eval does hold the whole domain, so in eval/full/all mode they stream it from n = 28
# (FssNN, ht-aes sh) and 27 (ht-aes mal, mal-auth: output and MAC per leaf); in `all`
# mode ht-aes stays stored, since its Gen has no streaming tree.
set -euo pipefail
cd "$(dirname "$0")/.."

MODE=gen
OUT_LIST=${OUT_LIST:-64,128}
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    gen|eval|full|all) MODE="$1"; shift ;;
    --max-in-bits|--reps|--points|--batch-log) ARGS+=("$1" "$2"); shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 1 ;;
  esac
done
[[ " ${ARGS[*]-} " == *" --max-in-bits "* ]] || ARGS+=(--max-in-bits 32)

if [[ $MODE == gen ]]; then
  OUT=results-gen
  FS=() AS=() AM=()
else
  OUT=results-eval
  FS=(--stream-from 28) AS=() AM=()
  # ht-aes refuses --stream for Gen, so `all` keeps its eval stored.
  [[ $MODE == all ]] || AS=(--stream-from 28) AM=(--stream-from 27)
fi
mkdir -p "$OUT"
cargo build --release -p floram-cprg -p half-tree -p floram-arith -p fssnn -p duoram -p ht-aes --examples

BIN=target/release/examples
S=(--sweep --out-list "$OUT_LIST" "${ARGS[@]}")
echo "floram"        && "$BIN/bench"              "$MODE" "${S[@]}" --stream-from 29                        | tee "$OUT"/floram.csv
echo "ht"            && "$BIN/bench-half-tree"    "$MODE" "${S[@]}" --stream-from 29 --variant ht           | tee "$OUT"/ht.csv
echo "ht-mal-ferret" && "$BIN/bench-half-tree"    "$MODE" "${S[@]}" --stream-from 27 --variant mal-ferret   | tee "$OUT"/ht-mal-ferret.csv
echo "floram-arith"  && "$BIN/bench-floram-arith" "$MODE" "${S[@]}" --stream-from 29                        | tee "$OUT"/floram-arith.csv
echo "fssnn-bin"     && "$BIN/bench-fssnn"        "$MODE" "${S[@]}" "${FS[@]}" --variant bin              | tee "$OUT"/fssnn-bin.csv
echo "fssnn-arith"   && "$BIN/bench-fssnn"        "$MODE" "${S[@]}" "${FS[@]}" --variant arith            | tee "$OUT"/fssnn-arith.csv
echo "duoram-2p"     && "$BIN/bench-duoram"       "$MODE" "${S[@]}" --stream-from 30 --variant 2p           | tee "$OUT"/duoram-2p.csv
echo "duoram-3p"     && "$BIN/bench-duoram"       "$MODE" "${S[@]}" --stream-from 30 --variant 3p           | tee "$OUT"/duoram-3p.csv
echo "ht-aes-sh"     && "$BIN/bench-ht-aes"       "$MODE" "${S[@]}" "${AS[@]}" --variant sh               | tee "$OUT"/ht-aes-sh.csv
echo "ht-aes-mal"    && "$BIN/bench-ht-aes"       "$MODE" "${S[@]}" "${AM[@]}" --variant mal              | tee "$OUT"/ht-aes-mal.csv
echo "ht-aes-mal-auth" && "$BIN/bench-ht-aes"     "$MODE" "${S[@]}" "${AM[@]}" --variant mal-auth         | tee "$OUT"/ht-aes-mal-auth.csv

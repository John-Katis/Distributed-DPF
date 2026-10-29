#!/usr/bin/env bash
# Runs the DPF benchmarks (Floram, HT, HT-mal with Ferret, Floram-arith,
# FssNN bin/arith, Duoram 2P/3P, ours: ht-aes {bin,arith} x {sh,mal} and the leakage-free mal-auth) over the same sweep and writes one CSV per
# protocol into results-gen/ (mode gen) or results-eval/ (eval, full, all).
#
#   [OUT_LIST=a,b,..] [SKIP_OURS=1] scripts/bench_all.sh [--min-in-bits n] [--max-in-bits n] [--max-in-bits-path n] [--append] [--reps R] [--reps-from n R] [--points P] [--batch-log b] [mode]
#
# SKIP_OURS=1 runs only the other papers' protocols and leaves the ht-aes
# CSVs as they are.
#
# mode is gen|eval|full|all (default gen). The sweep covers in-bits 20..=36
# for gen and 8..=32 otherwise (--min-in-bits, --max-in-bits) and out-bits
# OUT_LIST (default 64,128), so each output width has all protocols side by
# side. In gen mode FssNN and ours, whose Gen follows only the path to alpha,
# are measured up to in-bits 42 (--max-in-bits-path); every other protocol is
# measured up to 36 and its CSV gets estimated rows (variant `+est`) above its
# last measured width up to 42, by scripts/estimate_gen.py (computation x2 per
# bit, setup constant, communication, rounds and network time linear in n).
# So after a gen sweep every CSV has rows for in-bits 20..=42. --append adds
# the rows to the existing CSVs instead of starting them afresh, e.g. --append
# --min-in-bits 37 runs only FssNN and ours on 37..=42. --reps-from n R (gen default: 33 2) runs each point from in-bits n on
# as R separate 1-rep processes, one CSV row each, so the rows can be
# averaged (the bench reports the median, which for 2 reps is the slower
# one); below n a point runs once with --reps (default 5). Every (in-bits, out-bits)
# point is its own process, so a point that crashes (out of memory, panic)
# loses only itself: it is logged as a `# failed:` line in the CSV and the
# sweep moves on to the next protocol, since the larger points would not fit
# either. The failures are listed again at the end. Floram-arith and Duoram run Z_2^l on
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
# (FssNN, ht-aes sh) and 27 (ht-aes mal: output and MAC per leaf); in `all`
# mode ht-aes stays stored, since its Gen has no streaming tree.
set -uo pipefail
cd "$(dirname "$0")/.."

MODE=gen
OUT_LIST=${OUT_LIST:-64,128}
MIN_IN= MAX_IN= MAX_PATH= REPS_FROM= SPLIT= APPEND=0
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    gen|eval|full|all) MODE="$1"; shift ;;
    --min-in-bits) MIN_IN="$2"; shift 2 ;;
    --max-in-bits) MAX_IN="$2"; shift 2 ;;
    --max-in-bits-path) MAX_PATH="$2"; shift 2 ;;
    --append) APPEND=1; shift ;;
    --reps-from) REPS_FROM="$2" SPLIT="$3"; shift 3 ;;
    --reps|--points|--batch-log) ARGS+=("$1" "$2"); shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 1 ;;
  esac
done

if [[ $MODE == gen ]]; then
  : "${MIN_IN:=20}" "${MAX_IN:=36}" "${MAX_PATH:=42}" "${REPS_FROM:=33}" "${SPLIT:=2}"
else
  : "${MIN_IN:=8}" "${MAX_IN:=32}" "${MAX_PATH:=$MAX_IN}" "${REPS_FROM:=64}" "${SPLIT:=1}"
fi

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
cargo build --release -p floram-cprg -p half-tree -p floram-arith -p fssnn -p duoram -p ht-aes --examples || exit 1

BIN=target/release/examples
S=("${ARGS[@]}")
FAILED=()
# Ctrl-C stops the whole run instead of counting as a crashed point.
trap 'exit 130' INT

# run NAME BIN ARGS..: sweeps one protocol into $OUT/NAME.csv, one process
# per point (SPLIT 1-rep processes from REPS_FROM on); the header comes from
# the first process only, and with --append from none. FssNN and ours sweep
# up to MAX_PATH; the others up to MAX_IN and, in gen mode, are estimated
# from there (or from the last point that did not crash) up to MAX_PATH.
run() {
  local name=$1 csv="$OUT/$1.csv" n m i k reps first=1 code max=$MAX_IN
  shift
  case $name in fssnn-*|ht-aes-*) max=$MAX_PATH ;; esac
  echo "$name"
  if ((APPEND)); then first=0; else : > "$csv"; fi
  for ((n = MIN_IN; n <= max; n++)); do
    for m in ${OUT_LIST//,/ }; do
      k=1 reps=()
      ((n >= REPS_FROM)) && k=$SPLIT reps=(--reps 1)
      for ((i = 0; i < k; i++)); do
        "$@" --in-bits "$n" --out-bits "$m" "${reps[@]}" \
          | if ((first)); then cat; else grep -v -e '^# gen: ' -e '^# eval: ' -e '^# full: ' -e '^# net: '; fi \
          | tee -a "$csv"
        code=${PIPESTATUS[0]}
        first=0
        if ((code != 0)); then
          echo "# failed: in_bits=$n out_bits=$m exit=$code" | tee -a "$csv" >&2
          FAILED+=("$name at in_bits=$n out_bits=$m (exit $code)")
          break 3
        fi
      done
    done
  done
  if [[ $MODE == gen ]] && ((max < MAX_PATH)); then
    python3 -I scripts/estimate_gen.py "$csv" "$MAX_PATH"
  fi
}
run floram        "$BIN/bench"              "$MODE" "${S[@]}" --stream-from 29
run ht            "$BIN/bench-half-tree"    "$MODE" "${S[@]}" --stream-from 29 --variant ht
run ht-mal-ferret "$BIN/bench-half-tree"    "$MODE" "${S[@]}" --stream-from 27 --variant mal-ferret
run floram-arith  "$BIN/bench-floram-arith" "$MODE" "${S[@]}" --stream-from 29
run fssnn-bin     "$BIN/bench-fssnn"        "$MODE" "${S[@]}" "${FS[@]}" --variant bin
run fssnn-arith   "$BIN/bench-fssnn"        "$MODE" "${S[@]}" "${FS[@]}" --variant arith
run duoram-2p     "$BIN/bench-duoram"       "$MODE" "${S[@]}" --stream-from 30 --variant 2p
run duoram-3p     "$BIN/bench-duoram"       "$MODE" "${S[@]}" --stream-from 30 --variant 3p
if [[ ${SKIP_OURS:-0} != 1 ]]; then
  run ht-aes-sh-bin    "$BIN/bench-ht-aes" "$MODE" "${S[@]}" "${AS[@]}" --variant sh-bin
  run ht-aes-sh        "$BIN/bench-ht-aes" "$MODE" "${S[@]}" "${AS[@]}" --variant sh
  run ht-aes-mal       "$BIN/bench-ht-aes" "$MODE" "${S[@]}" "${AM[@]}" --variant mal
  run ht-aes-mal-arith "$BIN/bench-ht-aes" "$MODE" "${S[@]}" "${AM[@]}" --variant mal-arith
  # The leakage-free Gen (A1)-(A5); its keys and evaluation are those of ht-aes-mal.
  if [[ $MODE == gen ]]; then
    run ht-aes-mal-auth "$BIN/bench-ht-aes" gen "${S[@]}" --variant mal-auth
  fi
fi

if ((${#FAILED[@]})); then
  echo "failed (the sweep moved on to the next protocol):" >&2
  printf '  %s\n' "${FAILED[@]}" >&2
fi

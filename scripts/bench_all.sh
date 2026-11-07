#!/usr/bin/env bash
# Runs the DPF benchmarks (Floram, HT, HT-mal with Ferret, Floram-arith,
# FssNN bin/arith, Duoram 2P/3P, ours: ht-aes {bin,arith} x {sh,mal}) over the same sweep and writes one CSV per
# protocol into results-gen/ (mode gen) or results-eval/ (eval, full, all).
#
#   [OUT_LIST=a,b,..] [SKIP_OURS=1] [ONLY="name .."] scripts/bench_all.sh [--min-in-bits n] [--max-in-bits n] [--append] [--reps R] [--reps-from n R] [--points P] [--batch-log b] [mode]
#
# SKIP_OURS=1 runs only the other papers' protocols and leaves the ht-aes
# CSVs as they are. ONLY="fssnn-bin ht-aes-sh .." runs only the protocols
# with these CSV names (the first argument of each `run` below) and leaves
# the other CSVs as they are, e.g. to resume an interrupted sweep.
#
# mode is gen|eval|full|all (default gen). The CSVs cover in-bits 12..=42 for
# gen and 8..=32 otherwise (--min-in-bits, --max-in-bits) and out-bits
# OUT_LIST (default 64,128), so each output width has all protocols side by
# side. Every protocol keeps its tree in memory, as its paper does (no
# streaming tree), so it is measured only up to the largest in-bits whose
# stored tree fits in memory (the two numbers in each `run` line below, for
# Gen and for full-domain eval; peak RSS at out-bits 128 below ~18 GB of the
# 27 GB free, 2x per input bit) and estimated above it:
#
#   * gen: by scripts/estimate_gen.py (computation x2 per bit, setup constant,
#     communication, rounds and network time linear in n). FssNN's and ours'
#     Gen follows only the path to alpha (flat ~1 GB), so they are measured up
#     to 42.
#   * full: by scripts/estimate_full.py (time x2 per bit, ns per point
#     constant). Every full-domain eval holds the whole domain.
#
# Estimated rows have the variant suffix `+est` and reps 0. So after a sweep
# every CSV has rows for the whole range. eval and all are measured up to the
# smaller of the two widths and get no estimated rows. --append adds the rows
# to the existing CSVs instead of starting them afresh. Every point runs once
# with --reps (default 10); --reps-from n R instead runs each point from
# in-bits n on as R separate 1-rep processes, one CSV row each, so the rows
# can be averaged (scripts/paper_data.py takes their mean). Every (in-bits,
# out-bits) point is its own process, so a point that crashes (out of memory,
# panic) loses only itself: it is logged as a `# failed:` line in the CSV and
# the sweep moves on to the next protocol, since the larger points would not
# fit either. The failures are listed again at the end. Floram-arith and
# Duoram run Z_2^l on 64-bit words for l <= 64 and on 128-bit words above; at
# l = 128 every protocol takes one more PRG call per leaf for the output,
# since a 128-bit leaf has only 127 bits above its t-bit.
#
# The streaming tree (dpf_common::stream, `--stream`/`--stream-from` of every
# bench) stays in the code but is not used here.
set -uo pipefail
cd "$(dirname "$0")/.."

MODE=gen
OUT_LIST=${OUT_LIST:-64,128}
MIN_IN= MAX_IN= REPS=10 REPS_FROM=64 SPLIT=1 APPEND=0
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    gen|eval|full|all) MODE="$1"; shift ;;
    --min-in-bits) MIN_IN="$2"; shift 2 ;;
    --max-in-bits) MAX_IN="$2"; shift 2 ;;
    --append) APPEND=1; shift ;;
    --reps) REPS="$2"; shift 2 ;;
    --reps-from) REPS_FROM="$2" SPLIT="$3"; shift 3 ;;
    --points|--batch-log) ARGS+=("$1" "$2"); shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 1 ;;
  esac
done

if [[ $MODE == gen ]]; then
  : "${MIN_IN:=12}" "${MAX_IN:=42}"
  OUT=results-gen
else
  : "${MIN_IN:=8}" "${MAX_IN:=32}"
  OUT=results-eval
fi
mkdir -p "$OUT"
cargo build --release -p floram-cprg -p half-tree -p floram-arith -p fssnn -p duoram -p ht-aes --examples || exit 1

BIN=target/release/examples
S=("${ARGS[@]}")
FAILED=()
# Ctrl-C stops the whole run instead of counting as a crashed point.
trap 'exit 130' INT

# run NAME GEN_MAX FULL_MAX BIN ARGS..: sweeps one protocol into $OUT/NAME.csv,
# one process per point (SPLIT 1-rep processes from REPS_FROM on), measured up
# to GEN_MAX (gen) or FULL_MAX (full; the smaller one for eval and all), and
# in gen and full mode estimated from there (or from the last point that did
# not crash) up to MAX_IN. The header comes from the first process only, and
# with --append from none.
run() {
  local name=$1 csv="$OUT/$1.csv" n m i k reps first=1 code max
  case $MODE in
    gen) max=$2 ;;
    full) max=$3 ;;
    *) max=$(($2 < $3 ? $2 : $3)) ;;
  esac
  ((MAX_IN < max)) && max=$MAX_IN
  shift 3
  [[ -n ${ONLY:-} && " $ONLY " != *" $name "* ]] && return
  echo "$name"
  if ((APPEND)); then first=0; else : > "$csv"; fi
  for ((n = MIN_IN; n <= max; n++)); do
    for m in ${OUT_LIST//,/ }; do
      k=1 reps=(--reps "$REPS")
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
  if [[ $MODE == gen || $MODE == full ]] && ((max < MAX_IN)); then
    python3 -I "scripts/estimate_$MODE.py" "$csv" "$MAX_IN"
  fi
}
#   NAME             GEN FULL BIN                       ARGS
run floram           29  29   "$BIN/bench"              "$MODE" "${S[@]}"
run ht               29  29   "$BIN/bench-half-tree"    "$MODE" "${S[@]}" --variant ht
run ht-mal-ferret    26  27   "$BIN/bench-half-tree"    "$MODE" "${S[@]}" --variant mal-ferret
run floram-arith     29  29   "$BIN/bench-floram-arith" "$MODE" "${S[@]}"
run fssnn-bin        42  28   "$BIN/bench-fssnn"        "$MODE" "${S[@]}" --variant bin
run fssnn-arith      42  28   "$BIN/bench-fssnn"        "$MODE" "${S[@]}" --variant arith
run duoram-2p        29  28   "$BIN/bench-duoram"       "$MODE" "${S[@]}" --variant 2p
run duoram-3p        29  28   "$BIN/bench-duoram"       "$MODE" "${S[@]}" --variant 3p
if [[ ${SKIP_OURS:-0} != 1 ]]; then
  run ht-aes-sh-bin    42  28 "$BIN/bench-ht-aes" "$MODE" "${S[@]}" --variant sh-bin
  run ht-aes-sh        42  28 "$BIN/bench-ht-aes" "$MODE" "${S[@]}" --variant sh
  run ht-aes-mal       42  27 "$BIN/bench-ht-aes" "$MODE" "${S[@]}" --variant mal
  run ht-aes-mal-arith 42  27 "$BIN/bench-ht-aes" "$MODE" "${S[@]}" --variant mal-arith
fi

if ((${#FAILED[@]})); then
  echo "failed (the sweep moved on to the next protocol):" >&2
  printf '  %s\n' "${FAILED[@]}" >&2
fi

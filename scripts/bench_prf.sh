#!/usr/bin/env bash
# The PRF comparison of our template: the half-tree with AES–MMO (ht-aes
# sh-bin) against the full GGM tree with the DGH+21 LPN-PRG (ggm-lpn bin),
# each at several glue levels ν, and the two binary semi-honest baselines of
# the Floram line, Floram and Half-Tree. Separate from bench_all.sh: writes
# one CSV per protocol and ν into results-PRF/gen/ (mode gen) or
# results-PRF/full/ (mode full), and leaves results-gen/ and results-eval/
# as they are.
#
#   [OUT_LIST=a,b,..] [NU_LIST="1 5 17"] [NU_FULL=5] [ONLY="name .."] scripts/bench_prf.sh [gen|full|all]
#
# gen: in-bits 8..=42 (ours) and 8..=36 (Floram, Half-Tree, which expand the
# whole tree; estimated above 36 by scripts/estimate_gen.py), out-bits
# OUT_LIST (default 64,128), reps 5, and from in-bits 33 on two 1-rep
# processes per point (as bench_all.sh). Ours runs once per ν in NU_LIST, at
# every n > ν (CSV NAME-nuν). full: in-bits 8..=32; ours at ν = NU_FULL only,
# since ν changes evaluation by one XOR of M_ℓ per level; ggm-lpn (≈ 670 ns
# per point) measured up to 28 and estimated above by
# scripts/estimate_full.py. all: gen, then full. Every point is its own
# process; a crash is logged as `# failed:` and the sweep moves on to the
# next CSV. ONLY="ggm-lpn-bin-nu5 ht .." runs only the CSVs with these names.
set -uo pipefail
cd "$(dirname "$0")/.."

MODE=${1:-gen}
case $MODE in gen|full|all) ;; *) echo "usage: $0 [gen|full|all]" >&2; exit 1 ;; esac
OUT_LIST=${OUT_LIST:-64,128}
NU_LIST=${NU_LIST:-1 5 17}
NU_FULL=${NU_FULL:-5}
REPS_FROM=33 SPLIT=2

cargo build --release -p floram-cprg -p half-tree -p ht-aes -p ggm-lpn --examples || exit 1
BIN=target/release/examples
FAILED=()
trap 'exit 130' INT

# run MODE NAME MIN MAX EST BIN ARGS..: sweeps one CSV, results-PRF/MODE/NAME.csv,
# over in-bits MIN..=MAX and OUT_LIST, then estimates up to EST if EST > MAX.
run() {
  local mode=$1 name=$2 lo=$3 hi=$4 est=$5 csv="results-PRF/$1/$2.csv" n m i k reps first=1 code
  shift 5
  [[ -n ${ONLY:-} && " $ONLY " != *" $name "* ]] && return
  mkdir -p "results-PRF/$mode"
  echo "$mode $name"
  : > "$csv"
  for ((n = lo; n <= hi; n++)); do
    for m in ${OUT_LIST//,/ }; do
      k=1 reps=()
      [[ $mode == gen ]] && ((n >= REPS_FROM)) && k=$SPLIT reps=(--reps 1)
      for ((i = 0; i < k; i++)); do
        "$@" "$mode" --in-bits "$n" --out-bits "$m" "${reps[@]}" \
          | if ((first)); then cat; else grep -v -e '^# gen: ' -e '^# eval: ' -e '^# full: ' -e '^# net: '; fi \
          | tee -a "$csv"
        code=${PIPESTATUS[0]}
        first=0
        if ((code != 0)); then
          echo "# failed: in_bits=$n out_bits=$m exit=$code" | tee -a "$csv" >&2
          FAILED+=("$mode $name at in_bits=$n out_bits=$m (exit $code)")
          break 3
        fi
      done
    done
  done
  if ((est > hi)); then
    python3 -I "scripts/estimate_$mode.py" "$csv" "$est"
  fi
}

if [[ $MODE == gen || $MODE == all ]]; then
  run gen floram 8 36 42 "$BIN/bench" --stream-from 29
  run gen ht     8 36 42 "$BIN/bench-half-tree" --stream-from 29 --variant ht
  for nu in $NU_LIST; do
    run gen "ht-aes-sh-bin-nu$nu" $((nu + 1)) 42 0 "$BIN/bench-ht-aes" --variant sh-bin --nu "$nu"
    run gen "ggm-lpn-bin-nu$nu"   $((nu + 1)) 42 0 "$BIN/bench-ggm-lpn" --variant bin --nu "$nu"
  done
fi
if [[ $MODE == full || $MODE == all ]]; then
  run full floram 8 32 0 "$BIN/bench" --stream-from 29
  run full ht     8 32 0 "$BIN/bench-half-tree" --stream-from 29 --variant ht
  run full "ht-aes-sh-bin-nu$NU_FULL" $((NU_FULL + 1)) 32 0  "$BIN/bench-ht-aes" --stream-from 28 --variant sh-bin --nu "$NU_FULL"
  run full "ggm-lpn-bin-nu$NU_FULL"   $((NU_FULL + 1)) 28 32 "$BIN/bench-ggm-lpn" --stream-from 28 --variant bin --nu "$NU_FULL"
fi

if ((${#FAILED[@]})); then
  echo "failed (the sweep moved on to the next CSV):" >&2
  printf '  %s\n' "${FAILED[@]}" >&2
fi

#!/bin/sh
# Runs every harness and writes results/*.csv (one row per phase:
# lib,component,security,n,phase,bytes,rounds,msgs,secs,check).
set -e
cd "$(dirname "$0")"
mkdir -p results build/emp-cwd
# emp's Ferret caches its bootstrap in ./data/; run it where there is none.
(cd build/emp-cwd && ../bench_emp) > results/emp.csv
./build/bench_libote > results/libote.csv
(cd rust && cargo run --release -q) > results/rust.csv
(cd rust-cryprot && cargo run --release -q) > results/cryprot.csv

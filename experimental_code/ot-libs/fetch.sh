#!/bin/sh
# Fetches and builds emp-ot 0.3.0 (with emp-tool 0.3.0) and libOTe at pinned
# revisions into deps/ (git-ignored), then builds the two C++ harnesses into
# build/. Needs cmake ≥ 3.20, g++ ≥ 11, OpenSSL and python3.
set -e
cd "$(dirname "$0")"
mkdir -p deps build
P=$PWD/deps/install

clone() { # dir url rev
	[ -d "deps/$1" ] || git clone -q --recursive "$2" "deps/$1"
	git -C "deps/$1" checkout -q "$3"
}
clone emp-tool https://github.com/emp-toolkit/emp-tool.git 0.3.0
clone emp-ot https://github.com/emp-toolkit/emp-ot.git 0.3.0
clone libOTe https://github.com/osu-crypto/libOTe.git 5d419c34a3847515fac7572e7275a0aa20cf1159

cmake -S deps/emp-tool -B deps/emp-tool/build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$P
cmake --build deps/emp-tool/build -j && cmake --install deps/emp-tool/build
cmake -S deps/emp-ot -B deps/emp-ot/build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$P -DCMAKE_PREFIX_PATH=$P
cmake --build deps/emp-ot/build -j && cmake --install deps/emp-ot/build
g++ -O3 -march=native -std=c++17 -I$P/include cpp/emp/bench_emp.cpp -L$P/lib -Wl,-rpath,$P/lib \
	-lemp-tool -lssl -lcrypto -lpthread -o build/bench_emp

# libOTe: only the OT protocols (the NTT/RingLPN parts need <format>, GCC 13).
# The first build fetches SPIN (rev f2010e0), whose Block.h writes
# `alignas(16) __attribute__((may_alias))`, which g++ 11 rejects; the same
# attribute as [[gnu::may_alias]] parses. Patch it and build the library only
# (libOTe's own test suite does not build here).
(cd deps/libOTe && python3 build.py --sodium -DENABLE_SPIN=ON -DENABLE_SIMPLESTOT=ON -DENABLE_MR=ON \
	-DENABLE_MRR=OFF -DENABLE_MRR_TWIST=OFF -DENABLE_MR_KYBER=OFF -DENABLE_IKNP=ON -DENABLE_KOS=ON \
	-DENABLE_DELTA_KOS=ON -DENABLE_DELTA_IKNP=ON -DENABLE_SOFTSPOKEN_OT=ON -DENABLE_SILENTOT=ON \
	-DENABLE_KKRT=ON -DENABLE_OOS=ON -DENABLE_SILENT_VOLE=OFF -DENABLE_FOLEAGE=OFF -DENABLE_RINGLPN=OFF \
	-DENABLE_LOGVOLE=OFF -DENABLE_REGULAR_DPF=OFF -DENABLE_TERNARY_DPF=OFF -DENABLE_SPARSE_DPF=OFF \
	-DENABLE_PPRF=OFF) || true
sed -i 's|#define SPIN_MAY_ALIAS __attribute__((may_alias))|#define SPIN_MAY_ALIAS [[gnu::may_alias]]|' \
	deps/libOTe/out/spin/spin/src/kernels/Block.h
(cd deps/libOTe/out/spin && cmake --build out/build/linux -j)
cmake --build deps/libOTe/out/build/linux --target libOTe -j
./cpp/libote/build.sh

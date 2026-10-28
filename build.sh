#!/bin/sh
# Builds everything from a fresh clone:
#
#   ./build.sh          submodules, patches, libOTe, then cargo build --workspace --release
#   ./build.sh --test   the same, then cargo test --workspace --release
#
# The C++ libraries behind dpf-ot-sys are git submodules in third_party/,
# pinned to the revisions below:
#
# * emp-tool 0.3.0 and emp-ot 0.3.0 (headers only). Two patches from
#   crates/ot-sys/patches/ are applied: emp-tool's error() throws instead of
#   exiting, so a failed check (KOS, Ferret) becomes an Abort; emp-ot's
#   malicious Ferret calls error() when the SPCOT consistency check fails
#   (upstream only prints a message and carries on).
# * libOTe 5d419c34, built here with only the Masny–Rindal base OT (static
#   libs). Its cmake clones coproto, macoro, function2 and libdivide at pinned
#   revisions into third_party/libOTe/out/, so the first run needs network.
# * SCI from EzPC f24bf3e (compiled by crates/ot-sys/build.rs): KK13
#   (SplitKKOT), CrypTFlow2's bit triples and SiRNN's multiplexer.
#
# Needs git, cmake ≥ 3.20, g++ ≥ 11 with OpenMP, python3, OpenSSL headers and
# rustup (rust-toolchain.toml pins the Rust version). Every step is idempotent.
set -e
cd "$(dirname "$0")"
ROOT=$PWD

die() { echo "build.sh: $*" >&2; exit 1; }
for c in git cmake g++ python3 cargo; do
	command -v $c >/dev/null || die "$c not found"
done
v=$(cmake --version | sed -n 's/^cmake version \([0-9]*\)\.\([0-9]*\).*/\1 \2/p')
[ "${v% *}" -gt 3 ] || { [ "${v% *}" -eq 3 ] && [ "${v#* }" -ge 20 ]; } || die "cmake ≥ 3.20 needed"
[ "$(g++ -dumpversion | cut -d. -f1)" -ge 11 ] || die "g++ ≥ 11 needed"
printf '#include <openssl/ssl.h>\n#include <omp.h>\nint main(){}\n' |
	g++ -x c++ -fopenmp - -o /dev/null -lssl -lcrypto 2>/dev/null || die "OpenSSL headers (libssl-dev) or OpenMP (libgomp) missing"

# Not --recursive across the board: EzPC's own submodules (SEAL, eigen,
# cutlass, datasets; several hundred MB) are not needed, and of EzPC only
# SCI/src is compiled.
git submodule update --init third_party/emp-tool third_party/emp-ot
git submodule update --init --recursive third_party/libOTe
git submodule update --init --depth 1 third_party/EzPC
git -C third_party/EzPC sparse-checkout set SCI/src

patch() { # submodule patch-file
	if ! git -C "third_party/$1" apply --reverse --check "$ROOT/crates/ot-sys/patches/$2" 2>/dev/null; then
		git -C "third_party/$1" apply "$ROOT/crates/ot-sys/patches/$2"
	fi
}
patch emp-tool emp-tool-error-throws.patch
patch emp-ot emp-ot-ferret-check-aborts.patch

cd third_party/libOTe
python3 build.py --par=8 -DENABLE_MR=ON -DENABLE_SIMPLESTOT=OFF -DENABLE_MRR=OFF -DENABLE_MRR_TWIST=OFF \
	-DENABLE_MR_KYBER=OFF -DENABLE_IKNP=OFF -DENABLE_KOS=OFF -DENABLE_DELTA_KOS=OFF -DENABLE_DELTA_IKNP=OFF \
	-DENABLE_SOFTSPOKEN_OT=OFF -DENABLE_SILENTOT=OFF -DENABLE_SILENT_VOLE=OFF -DENABLE_KKRT=OFF -DENABLE_OOS=OFF \
	-DENABLE_FOLEAGE=OFF -DENABLE_RINGLPN=OFF -DENABLE_LOGVOLE=OFF -DENABLE_REGULAR_DPF=OFF \
	-DENABLE_TERNARY_DPF=OFF -DENABLE_SPARSE_DPF=OFF -DENABLE_PPRF=OFF -DENABLE_SPIN=OFF \
	-DENABLE_SODIUM=OFF -DENABLE_RELIC=OFF -DENABLE_BOOST=OFF || true
# libOTe's own test suite does not build with g++ 11; the library is all we need.
cmake --build out/build/linux --target libOTe -j8
ls out/build/linux/libOTe/liblibOTe.a out/build/linux/cryptoTools/cryptoTools/libcryptoTools.a \
	out/build/linux/coproto/coproto/libcoproto.a out/build/linux/macoro/macoro/libmacoro.a >/dev/null
cd "$ROOT"

cargo build --workspace --release
[ "$1" != --test ] || cargo test --workspace --release

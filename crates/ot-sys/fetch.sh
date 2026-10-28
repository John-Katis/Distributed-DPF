#!/bin/sh
# Fetches the OT libraries behind dpf-ot-sys into third_party/ at the repo
# root (git-ignored), at pinned revisions:
#
# * emp-tool 0.3.0 and emp-ot 0.3.0 (headers only; the OT code needs no
#   compiled emp-tool sources). emp-tool's error() exits the process; it is
#   patched to throw, so a failed check (KOS, Ferret) becomes an Abort.
# * libOTe 5d419c34, built with only the Masny–Rindal base OT (static libs).
#
# Needs git, cmake ≥ 3.20, g++ ≥ 11, python3 and OpenSSL headers.
set -e
cd "$(dirname "$0")/../.."
T=$PWD/third_party
mkdir -p "$T"

clone() { # dir url rev
	[ -d "$T/$1" ] || git clone -q --recursive "$2" "$T/$1"
	git -C "$T/$1" checkout -q "$3"
}
clone emp-tool https://github.com/emp-toolkit/emp-tool.git 0.3.0
clone emp-ot https://github.com/emp-toolkit/emp-ot.git 0.3.0
clone libOTe https://github.com/osu-crypto/libOTe.git 5d419c34a3847515fac7572e7275a0aa20cf1159

U=$T/emp-tool/emp-tool/utils/utils.hpp
if grep -q '^	exit(1);$' "$U"; then
	sed -i 's|^	exit(1);$|	throw std::runtime_error(s);|' "$U"
	sed -i 's|^#include <string>|#include <string>\n#include <stdexcept>|' "$T/emp-tool/emp-tool/utils/utils.h"
fi
grep -q 'throw std::runtime_error(s);' "$U"

cd "$T/libOTe"
python3 build.py --par=8 -DENABLE_MR=ON -DENABLE_SIMPLESTOT=OFF -DENABLE_MRR=OFF -DENABLE_MRR_TWIST=OFF \
	-DENABLE_MR_KYBER=OFF -DENABLE_IKNP=OFF -DENABLE_KOS=OFF -DENABLE_DELTA_KOS=OFF -DENABLE_DELTA_IKNP=OFF \
	-DENABLE_SOFTSPOKEN_OT=OFF -DENABLE_SILENTOT=OFF -DENABLE_SILENT_VOLE=OFF -DENABLE_KKRT=OFF -DENABLE_OOS=OFF \
	-DENABLE_FOLEAGE=OFF -DENABLE_RINGLPN=OFF -DENABLE_LOGVOLE=OFF -DENABLE_REGULAR_DPF=OFF \
	-DENABLE_TERNARY_DPF=OFF -DENABLE_SPARSE_DPF=OFF -DENABLE_PPRF=OFF -DENABLE_SPIN=OFF \
	-DENABLE_SODIUM=OFF -DENABLE_RELIC=OFF -DENABLE_BOOST=OFF || true
# libOTe's own test suite does not build with g++ 11; the library is all we need.
cmake --build out/build/linux --target libOTe -j8
ls out/build/linux/libOTe/liblibOTe.a out/build/linux/cryptoTools/cryptoTools/libcryptoTools.a \
	out/build/linux/coproto/coproto/libcoproto.a out/build/linux/macoro/macoro/libmacoro.a

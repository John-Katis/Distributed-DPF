#!/bin/sh
# Builds bench_libote against libOTe's build tree (deps/libOTe/out/build/linux).
# SPIN needs the one-line g++ 11 fix in fetch.sh (may_alias as [[gnu::may_alias]]).
set -e
cd "$(dirname "$0")/../.."
L=$PWD/deps/libOTe
B=$L/out/build/linux
mkdir -p build
c++ -O3 -DNDEBUG -std=c++20 -Wno-subobject-linkage -maes -msse2 -msse3 -mssse3 -msse4.1 -mpclmul -mavx -mavx2 -pthread \
  -DCRYPTOTOOLS_EDWARDS25519_ASM=1 \
  -I$L -I$B -I$L/cryptoTools -I$B/cryptoTools -I$L/out/coproto -I$B/coproto -I$L/out/macoro -I$B/macoro \
  -isystem $L/out/install/linux/include \
  cpp/libote/bench_libote.cpp -o build/bench_libote \
  $B/libOTe/liblibOTe.a $L/out/spin/out/build/linux/libspin.a $B/cryptoTools/cryptoTools/libcryptoTools.a $L/out/install/linux/lib/libsodium.a \
  $B/coproto/coproto/libcoproto.a $B/macoro/macoro/libmacoro.a

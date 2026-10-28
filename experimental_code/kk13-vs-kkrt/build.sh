#!/bin/sh
# Builds kkrt_triples against the libOTe build of ../ot-libs (run
# ../ot-libs/fetch.sh first; that build has KKRT enabled).
set -e
cd "$(dirname "$0")"
L=$PWD/../ot-libs/deps/libOTe
B=$L/out/build/linux
mkdir -p build
c++ -O3 -DNDEBUG -std=c++20 -march=native -w -pthread -DCRYPTOTOOLS_EDWARDS25519_ASM=1 \
  -I$L -I$B -I$L/cryptoTools -I$B/cryptoTools -I$L/out/coproto -I$B/coproto -I$L/out/macoro -I$B/macoro \
  -isystem $L/out/install/linux/include \
  kkrt_triples.cpp -o build/kkrt_triples \
  $B/libOTe/liblibOTe.a $L/out/spin/out/build/linux/libspin.a $B/cryptoTools/cryptoTools/libcryptoTools.a \
  $L/out/install/linux/lib/libsodium.a $B/coproto/coproto/libcoproto.a $B/macoro/macoro/libmacoro.a

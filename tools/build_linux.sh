#!/bin/bash

set -e

cd contrib/bitcoin-core/src/secp256k1
./autogen.sh
./configure --disable-shared --with-pic --enable-benchmark=no --enable-module-recovery --enable-module-schnorrsig --enable-module-ecdh --enable-experimental --enable-tests=no

num_jobs=4
if [ -f /proc/cpuinfo ]; then
    num_jobs=$(grep ^processor /proc/cpuinfo | wc -l)
fi

make clean
make -j $num_jobs

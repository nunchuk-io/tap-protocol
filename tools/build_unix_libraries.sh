#! /usr/bin/env bash
set -e

cd ./third_party/libwally-core
#$PWD/tools/cleanup.sh && $PWD/tools/autogen.sh

PREFIX="$PWD/lib/"
echo "Install $PREFIX"

./configure --prefix=$PREFIX --disable-swig-python --enable-static --enable-standard-secp

num_jobs=4
if [ -f /proc/cpuinfo ]; then
    num_jobs=$(grep ^processor /proc/cpuinfo | wc -l)
fi

make clean
make -j $num_jobs
make install

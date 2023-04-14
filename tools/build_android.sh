#!/bin/bash

if [ -z "$ANDROID_NDK" ]; then
   echo "export the ANDROID_NDK environment variable"
   exit 1
fi

# Allow the caller to specify which build to run
abiToBuild="all"
if [ -n "$ARCHS" ]; then
    abiRegex="^(all|armeabi-v7a|arm64-v8a|x86|x86_64)$"
    [[ $ARCHS =~ $abiRegex ]]
    
    if [[ $? == 0 ]]; then
        abiToBuild="$ARCHS"
        echo "manually selected ABI: $abiToBuild"
    else
        echo "invalid ARCHS environment variable, the following are accepted: all, armeabi-v7a, arm64-v8a, x86 or x86_64"
        exit 1
    fi
fi

# Ensure all commands after this point exit upon erroring
set -e

# Get the location of the android NDK build tools to build with
asm=""
if [ "$(uname)" == "Darwin" ]; then
    export TOOLCHAIN=$ANDROID_NDK/toolchains/llvm/prebuilt/darwin-x86_64
    asm="--with-asm=no"
else
    export TOOLCHAIN=$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64
fi

# create links to some toolchains binaries (https://github.com/android/ndk/issues/1324)
cd $TOOLCHAIN/bin/
for source in arm-linux-androideabi-*
do
    dest=${source/arm/armv7a}
    ln -sf $source $dest
done
cd -

# Set this to your minSdkVersion.
export API=21

cd contrib/bitcoin-core/src/secp256k1
./autogen.sh

pwd=`pwd`

build()
{
  abi=$1
  target=$2

  echo ""
  echo "-------------------------------------------------------------------------------"
  echo " Compiling for $abi"
  echo "-------------------------------------------------------------------------------"

  export TARGET=$target

  # Configure and build.
  export AR=$TOOLCHAIN/bin/$TARGET-ar
  export AS=$TOOLCHAIN/bin/$TARGET-as
  export CC=$TOOLCHAIN/bin/$TARGET$API-clang
  export CXX=$TOOLCHAIN/bin/$TARGET$API-clang++
  export LD=$TOOLCHAIN/bin/$TARGET-ld
  export RANLIB=$TOOLCHAIN/bin/$TARGET-ranlib
  export STRIP=$TOOLCHAIN/bin/$TARGET-strip

  ./configure --prefix="$pwd/build/android/$abi" --host=$TARGET $asm --disable-shared --with-pic --enable-benchmark=no --enable-module-recovery --enable-module-schnorrsig --enable-module-ecdh --enable-experimental --enable-tests=no

  local num_jobs=4
  if [ -f /proc/cpuinfo ]; then
      num_jobs=$(grep ^processor /proc/cpuinfo | wc -l)
  fi

  make clean
  make -j $num_jobs
  make install
}

if [[ $abiToBuild == "all" ]] || [[ $abiToBuild == "armeabi-v7a" ]]; then
    build armeabi-v7a   armv7a-linux-androideabi
fi
if [[ $abiToBuild == "all" ]] || [[ $abiToBuild == "arm64-v8a" ]]; then
    build arm64-v8a     aarch64-linux-android
fi
if [[ $abiToBuild == "all" ]] || [[ $abiToBuild == "x86" ]]; then
    build x86           i686-linux-android
fi
if [[ $abiToBuild == "all" ]] || [[ $abiToBuild == "x86_64" ]]; then
    build x86_64        x86_64-linux-android
fi

make clean

echo "done"

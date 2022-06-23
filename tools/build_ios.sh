#!/usr/bin/env sh
set -e # abort if any command fails

export PATH=$PATH:/opt/homebrew/bin/

pushd contrib/bitcoin-core/src/secp256k1
./autogen.sh

BUILD_DIR="$(pwd)/build"
num_jobs=4
if [ -f /proc/cpuinfo ]; then
  num_jobs=$(grep ^processor /proc/cpuinfo | wc -l)
fi

build() {
  SDK_NAME=$1 # iphonesimulator, iphoneos
  HOST=$2 # 'aarch64-apple-darwin' or 'x86_64-apple-darwin'
  EXTRA_CFLAGS=$3 # '-arch arm64 -mios...'
  CC="$(xcrun --sdk $SDK_NAME -f clang) -isysroot $(xcrun --sdk $SDK_NAME --show-sdk-path)"
  CC_FOR_BUILD="$(xcrun --sdk macosx -f clang) -isysroot $(xcrun --sdk macosx --show-sdk-path)"

  ./configure --disable-shared --host=$HOST --disable-shared --with-pic --enable-benchmark=no --enable-module-recovery --enable-module-schnorrsig --enable-module-ecdh --enable-experimental --enable-tests=no \
    CC="$CC $EXTRA_CFLAGS" \
    CPP="$CC $EXTRA_CFLAGS -E" \
    CC_FOR_BUILD="$CC_FOR_BUILD" \
    CPP_FOR_BUILD="$CC_FOR_BUILD -E" \

  make clean
  make -j $num_jobs

  SDK_DIR="${BUILD_DIR}/${SDK_NAME}"
  mkdir -p "${SDK_DIR}"

  #cp .libs/libsecp256k1.a "${SDK_DIR}/libsecp256k1-$HOST.a"
  cp .libs/libsecp256k1.a "${SDK_DIR}/libsecp256k1.a"

  make clean
}


if [[ $PLATFORM_NAME = "macosx" ]]; then
  TARGET_OS="macos"
elif [[ $PLATFORM_NAME = "iphonesimulator" ]]; then
  TARGET_OS="ios-simulator"
else
  TARGET_OS="ios"
fi

if [[ $CONFIGURATION = "Debug" ]]; then
  CONFIGURATION="debug"
else
  CONFIGURATION="release"
fi

ARCHES="${ARCHES:-arm64}"
LIBSECP256K1_EXECUTABLES=()

for ARCH in $ARCHES
do
  echo "Building for target $TARGET_ARCH"
  TARGET_ARCH=$ARCH
  if [[ $TARGET_ARCH = "arm64" ]]; then
    TARGET_ARCH="aarch64"
  fi

  build ${PLATFORM_NAME} ${TARGET_ARCH}-apple-darwin "-arch ${ARCH} -m${TARGET_OS}-version-min=7.0 -fembed-bitcode"
  #LIBSECP256K1_EXECUTABLES+=("${BUILD_DIR}/${PLATFORM_NAME}/libsecp256k1-${TARGET_ARCH}-apple-darwin.a")
done

echo "Done"

#xcrun --sdk $PLATFORM_NAME lipo -create "${LIBSECP256K1_EXECUTABLES[@]}" -output "${BUILD_DIR}/libsecp256k1"

popd
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=ios.toolchain.cmake -DPLATFORM=OS64
make all -j $num_jobs

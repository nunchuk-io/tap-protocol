#! /usr/bin/env bash
set -e

if [ -z "$ANDROID_NDK" ]; then
    export ANDROID_NDK=$(dirname `which ndk-build 2>/dev/null`)
fi
echo ${ANDROID_NDK:?}
if [ -z "$JAVA_HOME" ]; then
    export JAVA_HOME=$JAVA7_HOME
fi
echo ${JAVA_HOME:?}

cd ./third_party/libwally-core
$PWD/tools/cleanup.sh && $PWD/tools/autogen.sh

# List the android architectures supported by wally
function android_get_arch_list() {
    echo "armeabi-v7a arm64-v8a x86 x86_64"
}

# Get the location of the android NDK build tools to build with
function android_get_build_tools_dir() {
    if [ "$(uname)" == "Darwin" ]; then
        echo $ANDROID_NDK/toolchains/llvm/prebuilt/darwin-x86_64
    else
        echo $ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64
    fi
}

# Get the cross compile target for a given android architecture,
# used to determine the build tools to use.
# arch: An architecture from android_get_arch_list()
function android_get_cross_compile_target() {
    local arch=$1
    case $arch in
        armeabi-v7a) echo "armv7a-linux-androideabi";;
        arm64-v8a) echo "aarch64-linux-android";;
        x86) echo "i686-linux-android";;
        x86_64) echo "x86_64-linux-android";;
        *)
            echo "ERROR: Unknown arch $arch" >&2
            exit 1
            ;;
    esac
}

# Get the cross compile triplet for a given android architecture,
# passed as --host to configure
# arch: An architecture from android_get_arch_list()
# api:      The minimum Android API level to build for (e.g. 21)
function android_get_cross_compile_triplet() {
    local arch=$1 api=$3
    case $arch in
        armeabi-v7a) echo "armv7-none-linux-androideabi$api";;
        arm64-v8a) echo "aarch64-none-linux-android$api";;
        x86) echo "i686-none-linux-android$api";;
        x86_64) echo "x86_64-none-linux-android$api";;
        *)
            echo "ERROR: Unknown arch $arch" >&2
            exit 1
            ;;
    esac
}

# Create a toolchain configure and build wally for Android
# arch:     An architecture from android_get_arch_list()
# toolsdir: The directory for the NDK toolchain
# api:      The minimum Android API level to build for (e.g. 21)
# useropts: The users configure options e.g. --enable-swig-java
function android_build_wally() {
    local arch=$1 toolsdir=$2 api=$3
    shift 3
    local useropts=$*
    local target=$(android_get_cross_compile_target $arch)

    # Configure and build.
    export AR=$toolsdir/bin/$target-ar
    export AS=$toolsdir/bin/$target-as
    export CC=$toolsdir/bin/$target$api-clang
    export CXX=$toolsdir/bin/$target$api-clang++
    export LD=$toolsdir/bin/$target-ld
    export RANLIB=$toolsdir/bin/$target-ranlib
    export STRIP=$toolsdir/bin/$target-strip

    PREFIX="$PWD/android/$arch"
    #EPREFIX="$PWD/android/$arch/secp256k1"

    echo "Install $PREFIX"

    #./configure --prefix=$PREFIX --host=$(android_get_cross_compile_triplet $arch $api) \
    #  --disable-swig-python --enable-static --enable-standard-secp $useropts
    ./configure --prefix=$PREFIX --host=$target --disable-benchmark \
      --disable-swig-python --enable-static --enable-standard-secp $useropts
    local num_jobs=4
    if [ -f /proc/cpuinfo ]; then
        num_jobs=$(grep ^processor /proc/cpuinfo | wc -l)
    fi
    #PATH="$toolsdir/bin:$PATH" make -o configure clean
    #PATH="$toolsdir/bin:$PATH" make -o configure -j $num_jobs
    make clean
    make -j $num_jobs
    make install #--prefix=$PREFIX --exec-prefix=EPREFIX
}

# Build everything unless the user passed a single target name
ARCH_LIST=$(android_get_arch_list)

if [ -n "$1" ]; then
    ARCH_LIST="$1"
fi

for arch in $ARCH_LIST; do
    # Use API level 19 for non-64 bit targets for better device coverage
    api="19"
    if [[ $arch == *"64"* ]]; then
        api="21"
    fi

    # Location of the NDK tools to build with
    toolsdir=$(android_get_build_tools_dir)

    # Extra configure options
    useropts=""

    # Configure and build with the above options
    android_build_wally $arch $toolsdir $api $useropts

    # Copy and strip the build result
    #archdir=$PWD/release/lib/$arch
    #mkdir -p $archdir
    #$toolsdir/bin/llvm-strip -o $archdir/libwallycore.so $PWD/src/.libs/libwallycore.so
done

# Copy headers and Java wrapper
# The andoid release files can be used from Java or in native code
#mkdir -p $PWD/release/include # $PWD/release/src/swig_java/src/com/blockstream/libwally
#cp $PWD/include/*.h $PWD/release/include
#cp $PWD/src/swig_java/src/com/blockstream/libwally/Wally.java $PWD/release/src/swig_java/src/com/blockstream/libwally

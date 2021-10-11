#!/bin/bash

PLUGIN_REPO=$(realpath $(dirname "${BASH_SOURCE[0]}")/..)
cd "$PLUGIN_REPO"

#-----------------------------------------------------------------------------
# Install needed bins from APT if they're missing.
#-----------------------------------------------------------------------------

{
    cmake --version &&
    g++ --version &&
    make --version &&
    git --version &&
    wget --version &&
    unzip -h &&
    protoc --version &&
    autoconf --version &&
    automake --version &&
    libtoolize --version
} > /dev/null ||
sudo apt-get install -y cmake build-essential git wget unzip \
protobuf-compiler libprotobuf-dev autoconf automake libtool ||
{
    # If the user follows these instructions, the script can be used on systems
    # that lack apt-get or sudo.
    echo '
Unable to install required packages with apt-get.
You must install the following packages before running this script:
cmake g++ make git wget unzip protoc libprotobuf autoconf automake libtool'
    exit 1
}

#----------------------------------------------------------------------------
# Download newer protobuf if installed version < 3.2
#
# This affects Ubuntu 18.04 and Debian 9, which use protobuf 3.0.
# While GTIRB can be used with protobuf 3.0, building against it can break
# the ability to import files larger than 64 MiB.
#
# Protobuf 3.11 matches the version that Ghidra seems to use for its
# debugging protocol (Debugger-gadp) as of Ghidra 10.0.4.
# Matching that, or at least not using a newer version than that, helps avoid
# issues from having multiple different protobuf versions.
#----------------------------------------------------------------------------
PROTO_URL="https://github.com/protocolbuffers/protobuf/releases/download/v3.11.1/protobuf-java-3.11.1.tar.gz"

protoc=protoc
proto_lib=

if [[ -x protobuf/bin/protoc ]]; then
    protoc="$PLUGIN_REPO/protobuf/bin/protoc"
fi

IFS=. read -r -a proto_ver <<< "$($protoc --version)"

if [[ "${proto_ver[0]}" != "libprotoc 3" || "${proto_ver[1]}" -lt 2 ]]; then
    rm -rf protobuf &&
    mkdir protobuf &&
    cd protobuf || exit

    rm -f *.tar.gz *.zip
    if [[ ! -d protobuf-* || ! -x bin/protoc ]]; then
        wget "$PROTO_URL" &&
        tar xf protobuf-*.tar.gz &&
        rm -f *.tar.gz || exit

        extracted=(*)

        cd "$extracted" &&
        ./configure --prefix="$PLUGIN_REPO/protobuf" &&
        make -j8 &&
        make install &&
        cd .. &&
        rm -rf "${extracted[@]}" || exit
    fi

    cd ..
    protoc="$PLUGIN_REPO/protobuf/bin/protoc"
fi

if [[ "$protoc" != protoc ]]; then
    proto_lib="$PLUGIN_REPO/protobuf"
fi

#----------------------------------------------------------
# Clone and build GTIRB
#----------------------------------------------------------

cmake_args=(
    -DGTIRB_CXX_API=OFF -DGTIRB_PY_API=OFF -DGTIRB_CL_API=OFF
    -DGTIRB_DOCUMENTATION=OFF -DGTIRB_ENABLE_TESTS=OFF)

if [[ "$proto_lib" ]]; then
    cmake_args+=("-DCMAKE_PREFIX_PATH=$proto_lib")
fi

. "$PLUGIN_REPO/version.txt"

rm -rf gtirb-src
git clone https://github.com/GrammaTech/gtirb.git gtirb-src -b $GTIRB_BRANCH || exit

cd gtirb-src &&
$protoc --java_out=java --proto_path=proto proto/*.proto || exit

mkdir build &&
cd build &&
cmake "${cmake_args[@]}" .. &&
make || exit

pwd
if [ ! -f java/gtirb_api-*.jar -o ! -f java/protobuf-java-*.jar ]; then
    echo "Error: Unable to find the necessary JAR libraries"
    exit 1
fi

cd "$PLUGIN_REPO" &&
rm -f Gtirb/lib/*.jar &&
install -v gtirb-src/build/java/*.jar Gtirb/lib/ || exit

echo "Successfully finished building Java libs"

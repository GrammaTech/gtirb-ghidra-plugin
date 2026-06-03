#!/bin/bash

PLUGIN_REPO=$(realpath $(dirname "${BASH_SOURCE[0]}")/..)
cd "$PLUGIN_REPO"

#-----------------------------------------------------------------------------
# Install needed bins from APT if they're missing.
#-----------------------------------------------------------------------------

{
    cmake --version &&
    mvn --version &&
    g++ --version &&
    make --version &&
    git --version &&
    wget --version &&
    unzip -h &&
    protoc --version &&
    autoconf --version &&
    automake --version &&
    libtoolize --version
} > /dev/null 2>&1 || {
    echo "Attempting to install missing packages from apt..."
    sudo apt-get install -y cmake maven build-essential git wget unzip \
    protobuf-compiler libprotobuf-dev autoconf automake libtool
} || {
    # If the user follows these instructions, the script can be used on systems
    # that lack apt-get or sudo.
    echo '
Unable to install required packages with apt-get.
You must install the following packages before running this script:
cmake maven g++ make git wget unzip protoc libprotobuf
autoconf automake libtool'
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
# Find protoc: check for pre-downloaded binary in plugin repo, then PATH
PROTOC_URL="https://github.com/protocolbuffers/protobuf/releases/download/v27.0/protoc-27.0-linux-x86_64.zip"

if [[ -x "$PLUGIN_REPO/protoc/bin/protoc" ]]; then
    protoc="$PLUGIN_REPO/protoc/bin/protoc"
elif command -v protoc &>/dev/null; then
    # protobuf-java 4.x requires protoc >= 27; older system protoc generates 3.x-only code
    PROTOC_MAJOR=$(protoc --version 2>&1 | grep -oP '(?<=libprotoc )\d+')
    if [[ "${PROTOC_MAJOR:-0}" -ge 27 ]]; then
        protoc=protoc
    else
        echo "System protoc is too old ($(protoc --version)), downloading protoc 27.0..."
        wget -q "$PROTOC_URL" -O /tmp/protoc.zip &&
        unzip -q /tmp/protoc.zip -d "$PLUGIN_REPO/protoc" &&
        rm /tmp/protoc.zip || exit
        protoc="$PLUGIN_REPO/protoc/bin/protoc"
    fi
else
    echo "Downloading protoc 27.0..."
    wget -q "$PROTOC_URL" -O /tmp/protoc.zip &&
    unzip -q /tmp/protoc.zip -d "$PLUGIN_REPO/protoc" &&
    rm /tmp/protoc.zip || exit
    protoc="$PLUGIN_REPO/protoc/bin/protoc"
fi

echo "Using protoc: $protoc ($($protoc --version))"

#----------------------------------------------------------
# Find the local Gradle 8 binary
#----------------------------------------------------------
. "$PLUGIN_REPO/scripts/ghidra-defs.sh"
GRADLE_BIN=$(find_gradle) || exit

#----------------------------------------------------------
# Clone and build GTIRB
#----------------------------------------------------------

rm -rf gtirb-src
git clone https://github.com/GrammaTech/gtirb.git gtirb-src || exit

cd gtirb-src &&
$protoc --java_out=java --proto_path=proto proto/*.proto || exit

# Update protobuf-java version to match protoc 27.x
sed -i "s/protobuf-java:[0-9][^'\"[:space:]]*/protobuf-java:4.27.0/" java/build.gradle

cd java &&
"$GRADLE_BIN" build -x test || exit
GTIRB_JAR=($PWD/build/libs/*.jar)

if [[ ! -f ${GTIRB_JAR[0]} ]]; then
    echo "Error: Unable to find the necessary JAR library"
    exit 1
fi

cd "$PLUGIN_REPO" &&
rm -f Gtirb/lib/*.jar &&
install -v "${GTIRB_JAR[@]}" Gtirb/lib/ || exit

echo "Successfully finished building Java libs"

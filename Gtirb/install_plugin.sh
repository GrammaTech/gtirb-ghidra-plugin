#!/bin/bash
cd $(realpath $(dirname "${BASH_SOURCE[0]}"))

. ../scripts/ghidra-defs.sh

# Build with Gradle
gradle "$@" || exit

if [[ -z "$GHIDRA_INSTALL_DIR" ]]; then
    echo "Error: GHIDRA_INSTALL_DIR environment variable is not set."
    exit 1
fi

# Extract the plugin into Ghidra's extensions directory
PLUGIN_FILE="dist/$(basename "$GHIDRA_INSTALL_DIR")_$(date +"%Y%m%d")_Gtirb.zip"
rm -rf "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/Gtirb"
unzip -qd "$GHIDRA_INSTALL_DIR/Ghidra/Extensions" "$PLUGIN_FILE" &&
echo "Extracted $PLUGIN_FILE => $GHIDRA_INSTALL_DIR/Ghidra/Extensions"

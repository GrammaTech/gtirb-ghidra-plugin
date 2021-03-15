# GTIRB Ghidra Plugin

This repo contains the source for building a Ghidra plugin to handle
GTIRB files.

Some limitations:
 - Imports GTIRB created from ELF files (only)
 - Supported architectures are IA32, ARM, X86-64, and PPC32
 - File name must have ".gtirb" suffix (otherwise you will have to
   manually select the GTIRB loader)
 - Plugin is tied to Ghidra version, file name indicates which Ghidra
   version it is built for.

## Installation

To install the plugin:
 - Install Ghidra. Current release is 9.1.2:
   (https://ghidra-sre.org/ghidra_9.1.2_PUBLIC_20200212.zip)
 - Copy dist/ghidra_9.1.2_PUBLIC_Gtirb.zip in this directory
   into the Ghidra 9.1.2 extensions directory
   (INSTALLDIR/Extensions/Ghidra)
 - Start ghidra (e.g., INSTALLDIR/ghidraRun)
 - In workspace tool (not code listing), select File - Install
   Extensions - and select the plugin
 - Restart Ghidra.  You can now import GTIRB files.

## Demonstration:

A video demonstration of installing and using this plugin is available at
   [gtirb-ghidra-plugin-intro.mov](https://grammatech.github.io/gtirb-ghidra-plugin/gtirb-ghidra-plugin-intro.mov).

## Building

See the Installation section above to use the provided builds. To build from source instead:

 1. Install [Ghidra](https://ghidra-sre.org) and add the path to its extracted contents to your gradle properties. For example:
    ```sh
    unzip ghidra_9.2.2_PUBLIC_20201229.zip
    mkdir -p ~/.gradle
    echo "GHIDRA_INSTALL_DIR=$PWD/ghidra_9.2.2_PUBLIC" > ~/.gradle/gradle.properties
    ```
 2. Build [gtirb](https://github.com/GrammaTech/gtirb).
 3. Copy the gtirb\_api and protobuf-java jar files from the gtirb build's `java` directory to `Gtirb/lib`.
 4. Run gradle to build
    ```sh
    cd Gtirb
    gradle
    ```
 5. Install the resulting zip from `Gtirb/dist` into Ghidra.

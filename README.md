# GTIRB Ghidra Plugin

This repo contains the source for building a Ghidra plugin to handle
GTIRB files.

A version that handles loading a x86-64 GTIRB file is available in the
dist directory.  This version loads the bytes, symbols, functions, and
CFG information available in the GTIRB file, but does not (yet) use
any other information (e.g., other AuxData tables, symbolic
expressions).

Some limitations:
 - 64 bit little endian only
 - File name must have ".gtirb" suffix (otherwise you will have to
   manually select the GTIRB loader)
 - Plugin is tied to Ghidra version, file name indicates which Ghidra
   version it is built for.

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

Demonstration:
 - We have provided a demonstration video:
   [gtirb-ghidra-plugin-intro.mov](https://grammatech.github.io/gtirb-ghidra-plugin/gtirb-ghidra-plugin-intro.mov).

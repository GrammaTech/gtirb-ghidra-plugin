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

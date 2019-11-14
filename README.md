# GTIRB Ghidra Plugin

This repo contains the source for building a Ghidra plugin to handle GTIRB files.

A version that handles loading a x86-64 gtirb file is available in the dist directory. This version loads the image byte map and symbols availabe in the gtirb file, but does not (yet) use any other information (such as symbolic expressions, CFG, or anything in AuxData).

Some limitations:
 - 64 bit little endian only
 - File name must have ".gtirb" suffix (otherwise you will have to manually select the GTIRB loader)
 - Plugin is tied to Ghidra version, that is it was created for a specific Ghidra version (9.1).

To install the plugin:
 - Install Ghidra 9.1 release (https://ghidra-sre.org/ghidra_9.1_PUBLIC_20191023.zip)
 - Copy dist/ghidra_9.1_PUBLIC_20191113_gtirb.zip in this directory into the Ghidra 9.1 extensions directory (INSTALLDIR/Extensions/Ghidra)
 - Start ghidra (e.g. INSTALLDIR/ghidraRun)
 - In workspace tool (not code listing), select File - Install Extensions - and select the plugin
 - Restart Ghidra. You can now import gtirb files.

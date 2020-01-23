package com.grammatech.gtirb_ghidra_plugin;

import ghidra.program.model.listing.Program;

public class GtirbUtil {

    public static final boolean isGtIrb(Program program) {
        if (program != null) {
            if (program.getExecutablePath().endsWith(GtirbConstants.GTIRB_EXTENSION)) {
                return true;
            }
        }
        return false;
    }
}

package gtirbplugin;

import ghidra.program.model.listing.Program;

public class gtIrbPluginUtil {
	
    public final static boolean isGtIrb(Program program) {
        if (program != null) {
        	if (program.getExecutablePath().endsWith(gtIrbPluginConstants.GTIRB_EXTENSION)) {
        		return true;
        	}
        }
        return false;
    }

}

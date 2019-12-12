package gtirb;

import ghidra.program.model.listing.Program;

public class gtirbUtil {
	
    public final static boolean isGtIrb(Program program) {
        if (program != null) {
        	if (program.getExecutablePath().endsWith(gtirbConstants.GTIRB_EXTENSION)) {
        		return true;
        	}
        }
        return false;
    }

}

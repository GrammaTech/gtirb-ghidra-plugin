package gtIrbApi;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import ghidra.util.Msg;

public class IR {
	
	private proto.IROuterClass.IR protoIR;
	// Limit to one module or now. Actually should be list but I'm not sure how to get Ghidra to handle that
	private Module module;
	
	public IR() {
		this.protoIR = proto.IROuterClass.IR.getDefaultInstance();
	}
	
	public boolean loadFile(InputStream fileIn) {
        try {
            this.protoIR = proto.IROuterClass.IR.parseFrom(fileIn);
        } catch (FileNotFoundException fe) {
            Msg.error(this, "File not found");
            return false;
        } catch (IOException ie) {
            Msg.error(this, "Problem reading file");
            return false;
        }
        
        // Create a GTIRB API Module from the first protobuf Module
        proto.ModuleOuterClass.Module m = protoIR.getModulesList().get(0);
        this.module = new Module(m);
        if (module.initializeImageByteMap() != true) {
        	Msg.error(this,  "Error initializing ImageByteMap");
        	return false;
        }

        if (module.initializeSectionList() != true) {
        	Msg.error(this,  "Error initializing Section list");
        	return false;
        }
        
        return true;
	}
	
	public Module getModule() {
		return this.module;
	}

}

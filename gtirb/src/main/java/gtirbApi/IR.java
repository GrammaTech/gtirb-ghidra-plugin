package gtirbApi;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

// import ghidra.util.Msg;

public class IR {

    private proto.IROuterClass.IR protoIR;
    // Limit to one module or now. Actually should be list but I'm not sure how to get Ghidra to
    // handle that
    private Module module;

    public IR() {
        this.protoIR = proto.IROuterClass.IR.getDefaultInstance();
    }

    public boolean loadFile(InputStream fileIn) {
        try {
            this.protoIR = proto.IROuterClass.IR.parseFrom(fileIn);
        } catch (FileNotFoundException fe) {
            // Msg.error(this, "File not found");
            return false;
        } catch (IOException ie) {
            // Msg.error(this, "Problem reading file");
            return false;
        }

        // Create a GTIRB API Module from the first protobuf Module
        proto.ModuleOuterClass.Module m = protoIR.getModulesList().get(0);
        if (m == null) {
            // no modules?
            return false;
        }

        this.module = new Module(m);
        boolean imageByteMapInitialized = module.initializeImageByteMap();
        boolean sectionListInitialized = module.initializeSectionList();
        boolean symbolListInitialized = module.initializeSymbolList();
        boolean blockListInitialized = module.initializeBlockList();
        boolean proxyBlockListInitialized = module.initializeProxyBlockList();
        boolean dataObjectListInitialized = module.initializeDataObjectList();
        boolean auxDataInitialized = module.initializeAuxData();

        if ((!imageByteMapInitialized)
                || (!sectionListInitialized)
                || (!symbolListInitialized)
                || (!blockListInitialized)
                || (!proxyBlockListInitialized)
                || (!dataObjectListInitialized)
                || (!auxDataInitialized)) {
            return false;
        }
        return true;
    }

    public Module getModule() {
        return this.module;
    }
}

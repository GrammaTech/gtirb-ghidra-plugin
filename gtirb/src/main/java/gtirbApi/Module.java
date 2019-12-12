package gtirbApi;

import com.google.protobuf.ByteString;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Module {

    private proto.ModuleOuterClass.Module protoModule;
    private ImageByteMap imageByteMap;
    private ArrayList<Section> sectionList;
    private ArrayList<Symbol> symbolList;
    private ArrayList<DataObject> dataObjectList;
    private ArrayList<Block> blockList;
    private ArrayList<ProxyBlock> proxyBlockList;
    private AuxData auxData;
    private String name;

    // Set up constants for recognizing file formats
    public static final int GTIRB_FILE_FORMAT_UNDEFINED =
            proto.ModuleOuterClass.FileFormat.Format_Undefined_VALUE;
    public static final int GTIRB_FILE_FORMAT_COFF = proto.ModuleOuterClass.FileFormat.COFF_VALUE;
    public static final int GTIRB_FILE_FORMAT_ELF = proto.ModuleOuterClass.FileFormat.ELF_VALUE;
    public static final int GTIRB_FILE_FORMAT_PE = proto.ModuleOuterClass.FileFormat.PE_VALUE;
    public static final int GTIRB_FILE_FORMAT_IDAPRODB32 =
            proto.ModuleOuterClass.FileFormat.IdaProDb32_VALUE;
    public static final int GTIRB_FILE_FORMAT_IDAPRODB64 =
            proto.ModuleOuterClass.FileFormat.IdaProDb64_VALUE;
    public static final int GTIRB_FILE_FORMAT_XCOFF = proto.ModuleOuterClass.FileFormat.XCOFF_VALUE;
    public static final int GTIRB_FILE_FORMAT_MACHO = proto.ModuleOuterClass.FileFormat.MACHO_VALUE;
    public static final int GTIRB_FILE_FORMAT_RAW = proto.ModuleOuterClass.FileFormat.RAW_VALUE;

    // Set up constants for recognizing instruction set architectures
    public static final int GTIRB_ISA_UNDEFINED = proto.ModuleOuterClass.ISAID.ISA_Undefined_VALUE;
    public static final int GTIRB_ISA_IA32 = proto.ModuleOuterClass.ISAID.IA32_VALUE;
    public static final int GTIRB_ISA_PPC32 = proto.ModuleOuterClass.ISAID.PPC32_VALUE;
    public static final int GTIRB_ISA_X64 = proto.ModuleOuterClass.ISAID.X64_VALUE;
    public static final int GTIRB_ISA_ARM = proto.ModuleOuterClass.ISAID.ARM_VALUE;
    public static final int GTIRB_ISA_UNSUPPORTED =
            proto.ModuleOuterClass.ISAID.ValidButUnsupported_VALUE;

    public Module(proto.ModuleOuterClass.Module protoModule) {
        this.protoModule = protoModule;
        proto.ImageByteMapOuterClass.ImageByteMap protoImageByteMap = protoModule.getImageByteMap();
        this.imageByteMap = new ImageByteMap(protoImageByteMap);
        this.sectionList = new ArrayList<Section>();
        this.symbolList = new ArrayList<Symbol>();
        this.blockList = new ArrayList<Block>();
        this.proxyBlockList = new ArrayList<ProxyBlock>();
        this.dataObjectList = new ArrayList<DataObject>();
        this.name = protoModule.getName();
    }

    public boolean initializeImageByteMap() {

        proto.ImageByteMapOuterClass.ImageByteMap ibm = protoModule.getImageByteMap();
        proto.ByteMapOuterClass.ByteMap bm = ibm.getByteMap();
        List<proto.ByteMapOuterClass.Region> regionList = bm.getRegionsList();
        for (proto.ByteMapOuterClass.Region r : regionList) {
            long startAddress = r.getAddress();
            ByteString d = r.getData();
            byte[] byteArray = d.toByteArray();
            Region newRange = new Region(startAddress, byteArray);
            imageByteMap.addRegion(newRange);
        }
        return true;
    }

    public boolean initializeSectionList() {

        // For each section, add to sectionList in this class
        List<proto.SectionOuterClass.Section> protoSectionList = protoModule.getSectionsList();
        for (proto.SectionOuterClass.Section protoSection : protoSectionList) {
            Section newSection = new Section(protoSection);
            sectionList.add(newSection);
        }
        return true;
    }

    public boolean initializeSymbolList() {

        // For each symbol, add to symbolList in this class
        List<proto.SymbolOuterClass.Symbol> protoSymbolList = protoModule.getSymbolsList();
        for (proto.SymbolOuterClass.Symbol protoSymbol : protoSymbolList) {
            Symbol newSymbol = new Symbol(protoSymbol);
            symbolList.add(newSymbol);
        }
        return true;
    }

    public boolean initializeBlockList() {

        // For each block, add to blockList in this class
        List<proto.BlockOuterClass.Block> protoBlockList = protoModule.getBlocksList();
        for (proto.BlockOuterClass.Block protoBlock : protoBlockList) {
            Block newBlock = new Block(protoBlock);
            blockList.add(newBlock);
        }
        return true;
    }

    public boolean initializeProxyBlockList() {

        // For each proxy block, add to proxyBlockList in this class
        List<proto.ProxyBlockOuterClass.ProxyBlock> protoProxyBlockList =
                protoModule.getProxiesList();
        for (proto.ProxyBlockOuterClass.ProxyBlock protoProxyBlock : protoProxyBlockList) {
            ProxyBlock newProxyBlock = new ProxyBlock(protoProxyBlock);
            proxyBlockList.add(newProxyBlock);
        }
        return true;
    }

    public boolean initializeDataObjectList() {

        // For each data object, add to dataObjectList in this class
        List<proto.DataObjectOuterClass.DataObject> protoDataObjectList = protoModule.getDataList();
        for (proto.DataObjectOuterClass.DataObject protoDataObject : protoDataObjectList) {
            DataObject newDataObject = new DataObject(protoDataObject);
            dataObjectList.add(newDataObject);
        }
        return true;
    }

    public boolean initializeAuxData() {
        proto.AuxDataContainerOuterClass.AuxDataContainer auxDataContainer =
                protoModule.getAuxDataContainer();
        if (auxDataContainer == null) {
            return false;
        }
        this.auxData = new AuxData(auxDataContainer);

        Map<String, proto.AuxDataOuterClass.AuxData> auxDataMap = auxDataContainer.getAuxDataMap();
        if (auxDataMap == null) {
            return false;
        }
        proto.AuxDataOuterClass.AuxData protoFunctionEntries = auxDataMap.get("functionEntries");
        if (protoFunctionEntries != null) {
            auxData.initializeFunctionEntries(protoFunctionEntries);
        }

        proto.AuxDataOuterClass.AuxData protoFunctionBlocks = auxDataMap.get("functionBlocks");
        if (protoFunctionBlocks != null) {
            auxData.initializeFunctionBlocks(protoFunctionBlocks);
        }

        return true;
    }

    public byte[] getBytes(long startAddress, int size) {
        return imageByteMap.getBytes(startAddress, size);
    }

    public ArrayList<Section> getSections() {
        return this.sectionList;
    }

    public ArrayList<Symbol> getSymbols() {
        return this.symbolList;
    }

    public int getFileFormat() {
        return this.protoModule.getFileFormatValue();
    }

    public int getISA() {
        return this.protoModule.getIsaIdValue();
    }

    public ArrayList<Block> getBlockList() {
        return this.blockList;
    }

    public String getName() {
        return this.name;
    }

    public AuxData getAuxData() {
        return this.auxData;
    }
}

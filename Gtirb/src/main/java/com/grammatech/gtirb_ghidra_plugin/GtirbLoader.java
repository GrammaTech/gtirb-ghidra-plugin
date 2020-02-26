/*
 *  Copyright (C) 2020 GrammaTech, Inc.
 *
 *  This code is licensed under the MIT license. See the LICENSE file in the
 *  project root for license terms.
 *
 *  This project is sponsored by the Office of Naval Research, One Liberty
 *  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
 *  N68335-17-C-0700.  The content of the information does not necessarily
 *  reflect the position or policy of the Government and no official
 *  endorsement should be inferred.
 *
 */
package com.grammatech.gtirb_ghidra_plugin;

import com.grammatech.gtirb.ByteInterval;
import com.grammatech.gtirb.CFG;
import com.grammatech.gtirb.CodeBlock;
import com.grammatech.gtirb.DataBlock;
import com.grammatech.gtirb.DynamicSymbol;
import com.grammatech.gtirb.Edge;
import com.grammatech.gtirb.Edge.EdgeType;
import com.grammatech.gtirb.ElfRelocation;
import com.grammatech.gtirb.IR;
import com.grammatech.gtirb.Module;
import com.grammatech.gtirb.Node;
import com.grammatech.gtirb.ProxyBlock;
import com.grammatech.gtirb.Section;
import com.grammatech.gtirb.Serialization;
import com.grammatech.gtirb.Symbol;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

/** A {@link Loader} for processing GrammaTech Intermediate Representation for Binaries (GTIRB). */
public class GtirbLoader extends AbstractLibrarySupportLoader {

    public static final String GTIRB_NAME = "GrammaTech's IR for Binaries (GTIRB)";

    private Program program;
    private Memory memory;
    private FileBytes fileBytes;
    private Listing listing;
    private List<Option> options;
    private HashMap<String, GtirbFunction> functionMap;
    private HashMap<UUID, Long> byteIntervalLoadAddresses;

    private byte[] dynStrSectionContents;
    private ArrayList<DynamicSymbol> dynamicSymbols = new ArrayList<DynamicSymbol>();
    private ArrayList<ElfRelocation> elfRelocations = new ArrayList<>();
    private long loadOffset;
    private Namespace storageExtern;

    //
    // Process an ELF relocation section (section type RELA) according to
    // the Elf64_Rela structure defined in the ABI relocation chapter.
    // The parsed information is added to the relocation list for later processing.
    //
    private boolean getRelocations(Section section) {
        List<ByteInterval> byteIntervals = section.getByteIntervals();
        ByteInterval byteInterval = byteIntervals.get(0);
        Serialization serialization = new Serialization(byteInterval.getBytesDirect());
        while (serialization.getRemaining() > 0) {
            long relocOffset = serialization.getLong();
            long relocInfo = serialization.getLong();
            long relocAddend = serialization.getLong();
            ElfRelocation elfRelocation = new ElfRelocation(relocOffset, relocInfo, relocAddend, 0);
            elfRelocations.add(elfRelocation);
        }
        return true;
    }

    //
    // Get ELF section properties from AuxData.
    //
    // This includes information on section type and flags, which is needed to correctly process
    // the sections.
    //
    private boolean processElfSectionProperties(Map<UUID, ArrayList<Long>> elfSectionProperties) {
        // int sectionTypeREL = 9;
        // int sectionTypeRELA = 4;
        for (Map.Entry<UUID, ArrayList<Long>> entry : elfSectionProperties.entrySet()) {
            UUID sectionUuid = entry.getKey();
            Section section = (Section) Node.getByUuid(sectionUuid);
            ArrayList<Long> properties = entry.getValue();
            Long sectionType = properties.get(0);
            Long sectionFlags = properties.get(1);
            section.setElfSectionType(sectionType.longValue());
            section.setElfSectionFlags(sectionFlags.longValue());

            // Relocation sections: Currently only handling RELA, used by X86_64 ELF files.
            if (sectionType == ElfSectionHeaderConstants.SHT_RELA) {
                getRelocations(section);
            }
        }
        return true;
    }

    // Given a start index, return a string from a byte array buffer.
    // Assumes null terminated string and searches for the null,
    // Also assumes UTF-8
    private String byteArrayToString(byte[] byteArray, int startIndex) {
        String nameString;
        int position = startIndex;
        while (byteArray[position] != 0) {
            if (position < byteArray.length) position += 1;
            else break;
        }
        byte[] nameBytes = Arrays.copyOfRange(byteArray, startIndex, position);
        try {
            nameString = new String(nameBytes, "UTF-8");
        } catch (Exception e) {
            Msg.error(this, "Exception trying to convert bytes to string." + e);
            return null;
        }
        return nameString;
    }

    //
    // Get address information for the byte interval identifed by the given UUID
    //
    private long getByteIntervalAddress(UUID byteIntervalUuid) {
        Node referent = Node.getByUuid(byteIntervalUuid);
        if (referent == null) return 0;
        ByteInterval byteInterval = (ByteInterval) referent;
        return (byteInterval.getAddress());
    }

    private String getFunctionName(Module m, UUID feBlockUuid) {
        ArrayList<Symbol> symbols = m.getSymbols();
        UUID referentUuid;
        //
        // Iterate through symbols looking for the one whose referent is the
        // function entry block.
        //
        for (Symbol symbol : symbols) {
            referentUuid = symbol.getReferentByUuid();
            if (!referentUuid.equals(com.grammatech.gtirb.Util.NIL_UUID)) {
                Node referent = Node.getByUuid(referentUuid);
                if (referent == null) {
                    continue;
                }
                if (referentUuid.equals(feBlockUuid)) {
                    return symbol.getName();
                }
            }
        }
        return ("");
    }

    //
    // Populate the collection of known functions, including names, address, and sizes.
    // This will be will be used later when function symbols are resolved.
    //
    // Depends on gtirbApi Symbols and AuxData, so those must be loaded before calling this.
    //
    private boolean initializeFunctionMap(Module m) {
        this.functionMap = new HashMap<String, GtirbFunction>();
        String functionName;
        Map<UUID, ArrayList<UUID>> functionEntries = m.getAuxData().getFunctionEntries();
        Map<UUID, ArrayList<UUID>> functionBlocks = m.getAuxData().getFunctionBlocks();

        //
        // Process the Function Entries AuxData, which is a list of UUIDs of code blocks
        // that are entries to a function.
        for (Map.Entry<UUID, ArrayList<UUID>> entry : functionEntries.entrySet()) {
            UUID feUuid = entry.getKey();
            List<UUID> feBlockList = entry.getValue();

            // Find the function name by searching for the symbol that refers to this UUID
            UUID feFirstBlockUuid = feBlockList.get(0);
            functionName = getFunctionName(m, feFirstBlockUuid);
            if (functionName.length() <= 0) {
                continue;
            }
            if (functionMap.containsKey(functionName)) {
                Msg.info(this, "Duplicate function: " + functionName);
                continue;
            }

            // Get the code block of this function entry
            CodeBlock functionEntryBlock;
            Node functionEntryNode = Node.getByUuid(feFirstBlockUuid);
            if (functionEntryNode instanceof CodeBlock) {
                functionEntryBlock = (CodeBlock) functionEntryNode;
            } else {
                continue;
            }

            // Go through function block aux data, adding up the sizes to get the size of the
            // function
            int functionSize = 0;
            CodeBlock functionBlock;
            List<UUID> blockList = functionBlocks.get(feUuid);
            if (blockList == null) {
                // This list should not be null. In practice, sometimes it is.
                // This should be investigated as a possible GTIRB corruption
                // or serialization problem.
                // When it happens, use the entries list.
                Msg.info(this, "No code block list for " + functionName);
                blockList = functionEntries.get(feUuid);
            }
            for (UUID blockUuid : blockList) {
                functionBlock = (CodeBlock) Node.getByUuid(blockUuid);
                functionSize += functionBlock.getSize();
            }
            UUID byteIntervalUuid = functionEntryBlock.getByteIntervalUuid();
            long byteIntervalLoadAddress = 0;
            if (byteIntervalLoadAddresses.containsKey(byteIntervalUuid)) {
                byteIntervalLoadAddress = byteIntervalLoadAddresses.get(byteIntervalUuid);
            } else {
                Msg.info(this, "Unable to get load address for byte interval: " + functionName);
                continue;
            }

            // Compute load address of function (i.e. offset from image base address)
            long functionAddress = functionEntryBlock.getOffset() + byteIntervalLoadAddress;

            // Create a function object, to match with symbol later
            GtirbFunction function =
                    new GtirbFunction(functionName, functionAddress, functionSize, feUuid);
            functionMap.put(functionName, function);
        }
        return true;
    }

    private boolean setImageBase(String elfFileType, Program program) {
        //
        if (!GtirbLoaderOptionsFactory.hasImageBaseOption(this.options)) {
            Msg.info(this, "Using existing program image base of " + program.getImageBase());
            return true;
        }
        String imageBaseStr = GtirbLoaderOptionsFactory.getImageBaseOption(options);

        // Give a default in case parsing fails
        long defaultLoadAddress = 0x100000;
        long loadAddress = defaultLoadAddress;
        try {
            loadAddress = Long.parseLong(imageBaseStr, 16);
        } catch (Exception e) {
            Msg.info(this, "Unable to use provided value for Image Base " + e);
            Msg.info(this, "Reverting to default value.");
        }

        //
        // If binaryType is EXEC, use the addresses of the byte_intervals as load addresses.
        // so offset needs to be 0.
        //
        if (elfFileType.equals("EXEC")) {
            loadAddress = 0L;
        }
        this.loadOffset = loadAddress;
        try {
            AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
            Address imageBase = defaultSpace.getAddress(defaultLoadAddress, true);
            program.setImageBase(imageBase, true);
        } catch (Exception e) {
            Msg.error(this, "Can't set image base.", e);
            return false;
        }
        return true;
    }

    public void markAsCode(long start, long length) {
        // TODO: this should be in a common place, so all importers can communicate that something
        // is code or data.
        AddressSetPropertyMap codeProp = program.getAddressSetPropertyMap("CodeMap");
        if (codeProp == null) {
            try {
                codeProp = program.createAddressSetPropertyMap("CodeMap");
            } catch (DuplicateNameException e) {
                codeProp = program.getAddressSetPropertyMap("CodeMap");
            }
        }

        Address startAddress = program.getImageBase().add(start);
        Address endAddress = startAddress.add(length + 1);

        if (codeProp != null) {
            codeProp.add(startAddress, endAddress);
        }
    }

    public boolean addFunction(GtirbFunction function) {
        long start = function.getAddress();
        long end = start + function.getSize();
        if (end <= start) {
            Msg.info(this, "invalid address range: " + function.getName());
            return false;
        }
        Address imageBase = program.getImageBase();
        Address entryAddress = imageBase.add(start);
        Address lastAddress = imageBase.add(end - 1);
        AddressSet body = new AddressSet(entryAddress, lastAddress);
        try {
            this.listing.createFunction(
                    function.getName(), entryAddress, body, SourceType.IMPORTED);
        } catch (Exception e) {
            Msg.info(this, "Unable to add function: " + function.getName() + " " + e);
            return false;
        }
        Msg.debug(
                this,
                "Added "
                        + function.getName()
                        + " at "
                        + String.format("%08X", (start + 0x100000))
                        + " to "
                        + String.format("%08X", (end + 0x100000)));
        return true;
    }

    public boolean addSymbol(Symbol symbol, long address, Namespace namespace) {
        Address symbolAddress = program.getImageBase().add(address);
        String name = symbol.getName();
        symbol.setAddress(address);
        SymbolTable symbolTable = program.getSymbolTable();
        try {
            symbolTable.createLabel(symbolAddress, name, namespace, SourceType.IMPORTED);
        } catch (InvalidInputException e) {
            Msg.info(this, "addSymbol threw Invalid Input Exception " + e);
            return false;
        }
        return true;
    }

    private boolean addSectionBytes(Section section, MessageLog log, TaskMonitor monitor) {
        // If section has multiple byte intervals, use a suffix on the name.
        // Get section flags, and use them on all byte intervals in the section
        // Get address and size, and create a comment using section type
        // TODO: Must be an enum somewhere for this instead of using literals...
        //
        int byteIntervalIndex = 0;
        List<ByteInterval> byteIntervals = section.getByteIntervals();
        int elfSectionFlags = (int) section.getElfSectionFlags();
        boolean isWritable = ((elfSectionFlags & ElfSectionHeaderConstants.SHF_WRITE) > 0);
        // boolean isReadable = ((elfSectionFlags & ElfSectionHeaderConstants.SHF_ALLOC) == 0x02);
        boolean isReadable = true;
        boolean isExecutable = ((elfSectionFlags & ElfSectionHeaderConstants.SHF_EXECINSTR) > 0);
        int numberOfByteIntervals = byteIntervals.size();

        for (ByteInterval byteInterval : byteIntervals) {
            String byteIntervalName;
            if (numberOfByteIntervals == 1) {
                byteIntervalName = section.getName();
            } else {
                byteIntervalName = section.getName() + "_" + byteIntervalIndex++;
            }

            if (!byteInterval.hasAddress()) {
                Msg.info(
                        this,
                        "Unable to load byteInterval " + byteIntervalName + " (has no address).");
                continue;
            }
            Long byteIntervalAddress = byteInterval.getAddress();
            long byteIntervalSize = byteInterval.getSize();
            String byteIntervalComment =
                    GtirbUtil.getElfSectionType((int) section.getElfSectionType())
                            + String.format(
                                    " [%08x - %08x]",
                                    byteIntervalAddress, (byteIntervalAddress + byteIntervalSize));
            Address loadAddress = program.getImageBase().add(byteIntervalAddress);
            byte[] byteArray = com.grammatech.gtirb.Util.toByteArray(byteInterval.getBytes());
            if (byteArray == null) {
                Msg.info(
                        this,
                        "Unable to load byteInterval "
                                + byteIntervalName
                                + " (byteArray is empty).");
                continue;
            }
            InputStream dataInput = new ByteArrayInputStream(byteArray);
            try {
                MemoryBlockUtils.createInitializedBlock(
                        program,
                        false,
                        byteIntervalName,
                        loadAddress,
                        dataInput,
                        byteIntervalSize,
                        byteIntervalComment,
                        "GTIRB Loader",
                        isReadable,
                        isWritable,
                        isExecutable,
                        log,
                        monitor);
            } catch (AddressOverflowException e) {
                Msg.error(this, "Address Overflow Exception. " + e);
                return false;
            }
            this.byteIntervalLoadAddresses.put(byteInterval.getUuid(), byteIntervalAddress);
        }
        return true;
    }

    private boolean doRelocation(long relocAddr, long relocValue) {
        // subtract image base, otherwise it is doubled
        // long targetAddr = relocAddr - this.loadOffset;
        try {
            this.memory.setLong(this.program.getImageBase().add(relocAddr), relocValue);
        } catch (MemoryAccessException e) {
            Msg.info(this, "Unable to set do relocation " + e);
            return false;
        }
        return true;
    }

    private boolean processRelocations(
            ArrayList<Section> sections,
            long fakeExternalBlockAddress,
            TaskMonitor monitor,
            MessageLog log) {
        long dynamicSymbolAddress = fakeExternalBlockAddress;
        for (Section section : sections) {
            String sectionName = section.getName();
            if (sectionName.equals(".dynsym")) {
                List<ByteInterval> byteIntervals = section.getByteIntervals();
                ByteInterval byteInterval = byteIntervals.get(0);

                Serialization serialization = new Serialization(byteInterval.getBytesDirect());
                while (serialization.getRemaining() > 0) {
                    int symbolNameIndex = serialization.getInt();
                    byte symbolInfo = serialization.getByte();
                    byte symbolOther = serialization.getByte();
                    short symbolShndx = serialization.getShort();
                    long symbolValue = serialization.getLong();
                    long symbolSize = serialization.getLong();
                    String symbolName = byteArrayToString(dynStrSectionContents, symbolNameIndex);
                    DynamicSymbol dynamicSymbol =
                            new DynamicSymbol(
                                    symbolName,
                                    symbolInfo,
                                    symbolOther,
                                    symbolShndx,
                                    symbolValue,
                                    symbolSize);
                    dynamicSymbols.add(dynamicSymbol);
                    dynamicSymbol.setAddr(dynamicSymbolAddress);
                    dynamicSymbolAddress += 8;
                }
            }
        }

        int sizeOfExternalSymbolBlock = (dynamicSymbols.size() * 8) + 16;

        // Create an uninitialized block of this size to point external references to
        byte[] data = new byte[sizeOfExternalSymbolBlock];
        Arrays.fill(data, (byte) 0xC3); // (ret/retq)
        InputStream is = new ByteArrayInputStream(data);
        // subtract load offset, otherwise it is added twice!
        long externalOffset = fakeExternalBlockAddress - this.loadOffset;

        MemoryBlock externalBlock = null;
        try {
            externalBlock =
                    MemoryBlockUtils.createInitializedBlock(
                            program,
                            false,
                            "-external block-",
                            this.program.getImageBase().add(externalOffset),
                            is,
                            sizeOfExternalSymbolBlock,
                            "-external comment-",
                            "-external source-",
                            true,
                            true,
                            true,
                            log,
                            monitor);
        } catch (AddressOverflowException e) {
            Msg.error(this, "Create external memory block failed. " + e);
            return false;
        }
        if (externalBlock == null) {
            Msg.error(this, "Create external memory block failed.");
            return false;
        }

        for (ElfRelocation elfRelocation : elfRelocations) {
            DynamicSymbol relocationSymbol = dynamicSymbols.get(elfRelocation.getRelocSym());
            long relocAddr = elfRelocation.getRelocAddr();
            long relocAddend = elfRelocation.getRelocAddend();
            long symbolAddr = relocationSymbol.getAddr();

            // TODO: could verify reloc addr is valid for type and section pointed to
            switch (elfRelocation.getRelocType()) {
                case R_X86_64_64:
                    doRelocation(relocAddr, symbolAddr + relocAddend);
                    break;
                case R_X86_64_COPY:
                    doRelocation(relocAddr, symbolAddr);
                    break;
                case R_X86_64_GLOB_DAT:
                    doRelocation(relocAddr, symbolAddr);
                    break;
                case R_X86_64_JUMP_SLOT:
                    doRelocation(relocAddr, symbolAddr);
                    break;
                case R_X86_64_RELATIVE:
                    doRelocation(relocAddr, relocAddend + this.loadOffset);
                    break;
                case R_X86_64_NONE:
                case R_X86_64_PC32:
                case R_X86_64_GOT32:
                case R_X86_64_PLT32:
                case R_X86_64_GOTPCREL:
                default:
                    Msg.info(
                            this,
                            "Unhandled relocation " + elfRelocation.getRelocType().toString());
                    break;
            }
        }
        return true;
    }

    private boolean processControlFlowGraph(CFG cfg, Module module) {
        for (Edge edge : cfg.getEdgeList()) {
            long srcAddr = getBlockAddress(module, edge.getSourceUuid());
            long dstAddr = getBlockAddress(module, edge.getTargetUuid());

            if ((srcAddr == 0L) || (dstAddr == 0L)) {
                continue;
            }

            RefType flowType = null;
            if (edge.getEdgeType() == EdgeType.Type_Branch) {
                flowType =
                        (edge.isEdgeLabelConditional())
                                ? RefType.CONDITIONAL_JUMP
                                : RefType.UNCONDITIONAL_JUMP;
            } else if (edge.getEdgeType() == EdgeType.Type_Call) {
                flowType =
                        (edge.isEdgeLabelConditional())
                                ? RefType.CONDITIONAL_CALL
                                : RefType.UNCONDITIONAL_CALL;
            } else if (edge.getEdgeType() == EdgeType.Type_Fallthrough) {
                flowType = RefType.FALL_THROUGH;
            } else {
                continue;
            }

            // Now do it.
            this.program
                    .getReferenceManager()
                    .addMemoryReference(
                            this.program.getImageBase().add(srcAddr),
                            this.program.getImageBase().add(dstAddr),
                            flowType,
                            SourceType.IMPORTED,
                            0);
        }
        return true;
    }

    // Process symbol information
    //
    // A symbol is a label which also has an address, a symbol type and a source type.
    // This code adds all symbols as type CODE and source IMPORTED. Also the addresses
    // come from the gtirb referent UUID. See the gtirb data symbols example code.
    //
    private boolean processSymbols(ArrayList<Symbol> symbols) {

        boolean isFakeExternal = false;

        // Create namespace for external symbols
        SymbolTable symbolTable = program.getSymbolTable();
        try {
            this.storageExtern =
                    symbolTable.createNameSpace(null, Library.UNKNOWN, SourceType.IMPORTED);
        } catch (Exception e) {
            Msg.error(this, "Error creating external namespace: " + e);
            return false;
        }

        for (Symbol symbol : symbols) {

            // If this is a function, add it to the program
            if (functionMap.containsKey(symbol.getName())) {
                GtirbFunction function = functionMap.get(symbol.getName());
                addFunction(function);
                continue;
            }

            // If no payload, search the fake externals list for an assigned address
            UUID referentUuid = symbol.getReferentByUuid();
            if (referentUuid.equals(com.grammatech.gtirb.Util.NIL_UUID)) {
                for (DynamicSymbol dynamicSymbol : this.dynamicSymbols) {
                    if (dynamicSymbol.getName().equals(symbol.getName())) {
                        // Add fakeExternal symbol
                        long symbolOffset = dynamicSymbol.getAddr() - this.loadOffset;
                        addSymbol(symbol, symbolOffset, this.storageExtern);
                        isFakeExternal = true;
                        break;
                    }
                }
                if (isFakeExternal == false) {
                    Msg.info(
                            this,
                            "Symbol has no referrent and is not external, could not determine address: "
                                    + symbol.getName());
                }
                continue;
            }
            Node referent = Node.getByUuid(referentUuid);
            if (referent == null) {
                continue;
            } else if (referent instanceof CodeBlock) {
                CodeBlock codeBlock = (CodeBlock) referent;
                long symbolOffset =
                        getByteIntervalAddress(codeBlock.getByteIntervalUuid())
                                + codeBlock.getOffset();
                addSymbol(symbol, symbolOffset, null);
            } else if (referent instanceof DataBlock) {
                DataBlock dataBlock = (DataBlock) referent;
                long symbolOffset =
                        getByteIntervalAddress(dataBlock.getByteIntervalUuid())
                                + dataBlock.getOffset();
                addSymbol(symbol, symbolOffset, null);
            } else {
                for (DynamicSymbol dynamicSymbol : this.dynamicSymbols) {
                    if (dynamicSymbol.getName().equals(symbol.getName())) {
                        long symbolOffset = dynamicSymbol.getAddr() - this.loadOffset;
                        addSymbol(symbol, symbolOffset, this.storageExtern);
                        isFakeExternal = true;
                        break;
                    }
                }
                if (isFakeExternal == false) {
                    Msg.info(this, "Unable to determine symbol address: " + symbol.getName());
                }
            }
        }
        return true;
    }

    //
    // Get the address (offset from load address) of the block
    // with the given UUID.
    //
    //   Block is the UUID of a GTIRB Code, Data, or Proxy block.
    //   Address returned is the offset from base or load address.
    //
    //   This function gets the referred to block if possible, and
    //   computes the offset and returns it. If not possible, returns 0.
    //
    long getBlockAddress(Module module, UUID blockUuid) {
        if (blockUuid.equals(com.grammatech.gtirb.Util.NIL_UUID)) {
            return 0L;
        }
        Node uuidNode = Node.getByUuid(blockUuid);
        if (uuidNode == null) {
            return 0L;
        }
        if (uuidNode instanceof CodeBlock) {
            CodeBlock codeBlock = (CodeBlock) uuidNode;
            UUID byteIntervalUuid = codeBlock.getByteIntervalUuid();
            ByteInterval byteInterval = (ByteInterval) Node.getByUuid(byteIntervalUuid);
            long address = byteInterval.getAddress() + codeBlock.getOffset();
            return (address);
        } else if (uuidNode instanceof DataBlock) {
            DataBlock dataBlock = (DataBlock) uuidNode;
            UUID byteIntervalUuid = dataBlock.getByteIntervalUuid();
            ByteInterval byteInterval = (ByteInterval) Node.getByUuid(byteIntervalUuid);
            long address = byteInterval.getAddress() + dataBlock.getOffset();
            return (address);
        } else if (uuidNode instanceof ProxyBlock) {
            Symbol symbol = GtirbUtil.getSymbolByReferent(module, blockUuid);
            if (symbol != null) {
                return (symbol.getAddress());
            }
        }
        return (0L);
    }

    @Override
    public String getName() {
        return "GTIRB loader";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // TODO: Examine the bytes in 'provider' to determine if this loader can load it.  If it
        // can load it, return the appropriate load specifications.

        String path = provider.getAbsolutePath();
        if (path.endsWith(GtirbConstants.GTIRB_EXTENSION)) {
            LanguageCompilerSpecPair lcs = new LanguageCompilerSpecPair("x86:LE:64:default", "gcc");
            loadSpecs.add(new LoadSpec(this, 0, lcs, true));
        }
        return loadSpecs;
    }

    @Override
    protected void load(
            ByteProvider provider,
            LoadSpec loadSpec,
            List<Option> options,
            Program program,
            TaskMonitor monitor,
            MessageLog log)
            throws CancelledException, IOException {

        monitor.setMessage("Loading GTIRB ...");
        program.setExecutableFormat(GtirbLoader.GTIRB_NAME);
        this.program = program;
        this.memory = program.getMemory();
        this.listing = program.getListing();
        this.options = options;

        //
        // Load the GTIRB file into the IR
        //
        InputStream fileIn = provider.getInputStream(0);
        IR ir = IR.loadFile(fileIn);
        if (ir == null) {
            Msg.error(this, "Unable to load GTIRB file");
            return;
        }

        //
        // TODO: The operations that follow should be done per module.
        // For the moment only the first module is getting loaded.
        Module module = ir.getModule();

        //
        // Examine the modules ISA and File Format. Currently only support X86_64/ELF
        //
        // TODO: There is a sequencing problem with file format and ISA identification.
        // Language specification (ISA/Endian/FileFormat) is chosen before choosing which loader to
        // use.
        //
        if (module.getFileFormat() == Module.FileFormat.ELF) {
            Msg.info(this, "File type is ELF.");
        } else {
            Msg.error(
                    this,
                    "File Format is not ELF (ID = "
                            + module.getFileFormat()
                            + "), so far only ELF is supported");
            return;
        }
        if (module.getISA() == Module.ISA.X64) {
            Msg.info(this, "ISA is X64.");
        } else {
            Msg.error(
                    this,
                    "ISA is not X64 (ID = " + module.getISA() + "), so far only X86 is supported");
            return;
        }

        //
        // Set image base / load address
        //
        // Calling setImageBase() reads the requested load address from the
        // UI load options and sets the programs load address accordingly.
        // However, if the ELF type is EXEC, it contains (virtual) load
        // addresses that should be honored, so, make that adjustment here.
        // Either way, store this.loadOffset as the number to use when creating
        // a ghidra address.
        //
        String elfFileType = "EXEC";
        ArrayList<String> binaryTypeList = module.getAuxData().getBinaryType();
        if (binaryTypeList != null) {
            // This is generally a list with only one item. If there are multiple
            // the last one is used.
            for (String binaryType : binaryTypeList) {
                Msg.info(this, "Module type:    " + binaryType);
                elfFileType = binaryType;
            }
        } else {
            Msg.info(this, "Module type defaulting to EXEC");
        }
        if (!setImageBase(elfFileType, program)) {
            // if this fails, no alternative but to exit loader.
            return;
        }

        //
        // Process ELF Sections
        //
        // First get elfSectionProperties from auxData, setting flags and type in the
        // Gtirb section objects.
        // Then iterate through the sections to:
        // - Add bytes from the Gtirb section into the program listing
        // - Determine the end of the loaded image (max address) so that a "fake"
        //   external block can be placed after to the program, to resolve external
        //   references
        // - Mark those sections containing executable instructions (according to
        //   the section flag) as code to assist later analysis.
        //
        monitor.setMessage("Processing program sections...");
        Map<UUID, ArrayList<Long>> elfSectionProperties =
                module.getAuxData().getElfSectionProperties();
        if (elfSectionProperties != null) {
            processElfSectionProperties(elfSectionProperties);
        }

        ArrayList<Section> sections = module.getSections();
        long maxAddress = 0L;
        this.byteIntervalLoadAddresses = new HashMap<UUID, Long>();
        for (Section section : sections) {
            boolean retval = addSectionBytes(section, log, monitor);
            if (retval != true) {
                Msg.error(this, "Section bytes add failed");
                return;
            }

            //
            // Get byte interval address information, to determine where to put fakeExternal block
            //
            String sectionName = section.getName();
            List<ByteInterval> byteIntervals = section.getByteIntervals();
            ByteInterval byteInterval = byteIntervals.get(0);
            long lastAddr = byteInterval.getAddress() + byteInterval.getSize() + this.loadOffset;
            if (lastAddr > maxAddress) {
                maxAddress = lastAddr;
            }

            //
            // If this is ".dynstr", store the contents, becuase we will need to search for symbol
            // names there
            // TODO: This should be determined from elfSectionProperties instead of being a
            // constant!
            if (sectionName.equals(".dynstr")) {
                dynStrSectionContents = byteInterval.getBytesDirect();
            }
            // TODO: Must be an enum somewhere for this instead of using literals...
            if ((section.getElfSectionFlags() & ElfSectionHeaderConstants.SHF_EXECINSTR) > 0)
                markAsCode(byteInterval.getAddress(), byteInterval.getSize());
        }

        //
        // Get function information from AuxData
        monitor.setMessage("Initializing function map...");
        if (!initializeFunctionMap(module)) {
            return;
        }

        // Process relocations
        monitor.setMessage("Processing relocations...");
        if (!processRelocations(sections, maxAddress + 8, monitor, log)) {
            return;
        }

        // Process symbol information
        monitor.setMessage("Initializing symbol table...");
        if (!processSymbols(module.getSymbols())) {
            return;
        }

        // Process GTIRB CFG
        CFG cfg = ir.getCfg();
        if (!processControlFlowGraph(cfg, module)) {
            return;
        }

        //
        // Further TODOs:
        //     Import auxdata comments

    }

    @Override
    public List<Option> getDefaultOptions(
            ByteProvider provider,
            LoadSpec loadSpec,
            DomainObject domainObject,
            boolean isLoadIntoProgram) {
        List<Option> list =
                super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

        try {
            GtirbLoaderOptionsFactory.addOptions(list, provider, loadSpec);
        } catch (Exception e) {
            Msg.error(this, "Error while generating GTIRB import options", e);
            // ignore here, will catch later
        }

        return list;
    }

    @Override
    public String validateOptions(
            ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

        // TODO: If this loader has custom options, validate them here.  Not all options require
        // validation.

        return super.validateOptions(provider, loadSpec, options, program);
    }

    public FileBytes getFileBytes() {
        return fileBytes;
    }

    public void setFileBytes(FileBytes fileBytes) {
        this.fileBytes = fileBytes;
    }

    public Listing getListing() {
        return listing;
    }

    public void setListing(Listing listing) {
        this.listing = listing;
    }

    public Memory getMemory() {
        return memory;
    }

    public void setMemory(Memory memory) {
        this.memory = memory;
    }
}

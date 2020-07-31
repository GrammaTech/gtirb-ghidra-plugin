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
import com.grammatech.gtirb.Block;
import com.grammatech.gtirb.CodeBlock;
import com.grammatech.gtirb.DataBlock;
import com.grammatech.gtirb.Edge;
import com.grammatech.gtirb.Edge.EdgeType;
import com.grammatech.gtirb.IR;
import com.grammatech.gtirb.Module;
import com.grammatech.gtirb.Node;
import com.grammatech.gtirb.Offset;
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
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.disassemble.Disassembler;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

/**
 * A {@link Loader} for processing GrammaTech Intermediate Representation for
 * Binaries (GTIRB).
 */
public class GtirbLoader extends AbstractLibrarySupportLoader {

    public static final String GTIRB_NAME =
        "GrammaTech's IR for Binaries (GTIRB)";

    private Program program;
    private Memory memory;
    private TaskMonitor monitor;
    private FileBytes fileBytes;
    private Listing listing;
    private Disassembler disassembler;

    private List<Option> options;
    private HashMap<String, GtirbFunction> functionMap;

    private byte[] dynStrSectionContents;
    private ArrayList<DynamicSymbol> dynamicSymbols =
        new ArrayList<DynamicSymbol>();
    private ArrayList<ElfRelocation> elfRelocations = new ArrayList<>();
    private long loadOffset;
    private Namespace storageExtern;
    static private IR ir;

    public static IR getIR() { return ir; }
    //
    // Process an ELF relocation section (section type RELA) according to
    // the Elf64_Rela structure defined in the ABI relocation chapter.
    // The parsed information is added to the relocation list for later
    // processing.
    //
    private boolean getRelocations(Section section) {
        List<ByteInterval> byteIntervals = section.getByteIntervals();
        ByteInterval byteInterval = byteIntervals.get(0);
        Serialization serialization =
            new Serialization(byteInterval.getBytesDirect());
        while (serialization.getRemaining() > 0) {
            long relocOffset = serialization.getLong();
            long relocInfo = serialization.getLong();
            long relocAddend = serialization.getLong();
            ElfRelocation elfRelocation =
                new ElfRelocation(relocOffset, relocInfo, relocAddend, 0);
            elfRelocations.add(elfRelocation);
        }
        return true;
    }

    //
    // Get ELF section properties from AuxData.
    //
    // This includes information on section type and flags, which is needed to
    // correctly process the sections.
    //
    private boolean processElfSectionProperties(
        Map<UUID, ArrayList<Long>> elfSectionProperties) {
        for (Map.Entry<UUID, ArrayList<Long>> entry :
             elfSectionProperties.entrySet()) {
            UUID sectionUuid = entry.getKey();
            Section section = (Section)Node.getByUuid(sectionUuid);
            ArrayList<Long> properties = entry.getValue();
            Long sectionType = properties.get(0);
            Long sectionFlags = properties.get(1);
            section.setElfSectionType(sectionType.longValue());
            section.setElfSectionFlags(sectionFlags.longValue());

            // Relocation sections: Currently only handling RELA, used by X86_64
            // ELF files.
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
            if (position < byteArray.length)
                position += 1;
            else
                break;
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
    // Populate the collection of known functions, including names, address, and
    // sizes. This will be will be used later when function symbols are
    // resolved.
    //
    // Depends on gtirbApi Symbols and AuxData, so those must be loaded before
    // calling this.
    //
    private boolean initializeFunctionMap(Module m) {
        this.functionMap = new HashMap<String, GtirbFunction>();
        String functionName;
        Map<UUID, ArrayList<UUID>> functionEntries =
            m.getAuxData().getFunctionEntries();
        Map<UUID, ArrayList<UUID>> functionBlocks =
            m.getAuxData().getFunctionBlocks();

        //
        // Process the Function Entries AuxData, which is a list of UUIDs of
        // code blocks that are entries to a function.
        for (Map.Entry<UUID, ArrayList<UUID>> entry :
             functionEntries.entrySet()) {
            UUID feUuid = entry.getKey();
            List<UUID> feBlockList = entry.getValue();

            // Find the function name by searching for the symbol that refers to
            // this UUID
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
                functionEntryBlock = (CodeBlock)functionEntryNode;
            } else {
                continue;
            }

            long byteIntervalAddress =
                functionEntryBlock.getBlock().getByteInterval().getAddress();
            long functionAddress =
                byteIntervalAddress + functionEntryBlock.getOffset();

            List<UUID> blockList = functionBlocks.get(feUuid);
            if (blockList == null) {
                // This list should not be null. In practice, sometimes it is.
                // This should be investigated as a possible GTIRB corruption
                // or serialization problem.
                // When it happens, use the entries list.
                Msg.info(this, "No code block list for " + functionName);
                blockList = functionEntries.get(feUuid);
            }

            // Adding the size of the blocks listed as function blocks is
            // USUALLY correct however not always. Sometimes there is a gap in
            // blocks! Typically occupied by a data block. Theoretically the
            // code could be generated that way, just seems unlikely. Anyway
            // that forces me to look at the address range covered by the
            // blocks, smallest address to largest. To make is more complicated,
            // the blocks can be in different byte intervals, so I have to look
            // up the byte interval for every block, since the block itself does
            // not have an address, only an offset.
            long minAddress = Long.MAX_VALUE;
            long maxAddress = 0;
            for (UUID blockUuid : blockList) {
                CodeBlock functionBlock = (CodeBlock)Node.getByUuid(blockUuid);
                long startAddress =
                    functionBlock.getBlock().getByteInterval().getAddress() +
                    functionBlock.getOffset();
                long endAddress = startAddress + functionBlock.getSize();
                minAddress = Math.min(startAddress, minAddress);
                maxAddress = Math.max(endAddress, maxAddress);
            }
            int functionSize = (int)(maxAddress - minAddress);

            // Create a function object, to match with symbol later
            GtirbFunction function = new GtirbFunction(
                functionName, functionAddress, functionSize, feUuid);
            functionMap.put(functionName, function);
        }
        return true;
    }

    private boolean setImageBase(String elfFileType, Program program) {
        //
        if (!GtirbLoaderOptionsFactory.hasImageBaseOption(this.options)) {
            Msg.info(this, "Using existing program image base of " +
                               program.getImageBase());
            return true;
        }
        String imageBaseStr =
            GtirbLoaderOptionsFactory.getImageBaseOption(options);

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
        // If binaryType is EXEC, use the addresses of the byte_intervals as
        // load addresses. so offset needs to be 0. Otherwise use the load
        // address established above. Either way store the result as
        // this.loadOffset. Note that proper setting of elfFileType requires ELF
        // info in Aux Data. In case there isn't any, the default ELF file type
        // is EXEC.
        //
        if (elfFileType.equals("EXEC")) {
            loadAddress = 0L;
        }
        this.loadOffset = loadAddress;
        try {
            AddressSpace defaultSpace =
                program.getAddressFactory().getDefaultAddressSpace();
            Address imageBase = defaultSpace.getAddress(loadAddress, true);
            program.setImageBase(imageBase, true);
        } catch (Exception e) {
            Msg.error(this, "Can't set image base.", e);
            return false;
        }
        return true;
    }

    private void markAsCode(long start, long length) {
        // Am I having a problem with unwanted flows
        // that could be fixed just by leaving one-byte gaps?
        // length = length - 1; <= did not fix anything
        AddressSetPropertyMap codeProp =
            program.getAddressSetPropertyMap("CodeMap");

        if (codeProp == null) {
            try {
                codeProp = program.createAddressSetPropertyMap("CodeMap");
            } catch (DuplicateNameException e) {
                codeProp = program.getAddressSetPropertyMap("CodeMap");
            }
        }

        Address startAddress = program.getImageBase().add(start);
        Address endAddress = startAddress.add(length);

        if (codeProp != null) {
            codeProp.add(startAddress, endAddress);
        }
    }

    private boolean addFunction(GtirbFunction function) {
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

        //
        // Special handling for GTIRB generated by CodeSurfer
        //
        // In the Codesurfer generated GTIRB, externally linked
        // functions manifest as a symbol with no referrent (which
        // represents the unresolved library reference) and a function
        // with the prefix "__thunk", which represents the stub that the
        // the program references to get the actual address.
        //
        // To resolve this in Ghidra, create a function (without the
        // prefix) and use Ghidra's API for external references.
        //
        // Later, in prcessSymbols, you will see a matching symbol
        // with no referent; if it matches a function, then let it go.
        //
        if (function.getName().matches("^__thunk_.*")) {
            Function f;
            ExternalLocation extLoc;
            String realName = function.getName().replaceFirst("^__thunk_", "");
            try {
                f = this.listing.createFunction(realName, entryAddress, body,
                                                SourceType.IMPORTED);
                extLoc = program.getExternalManager().addExtFunction(
                    Library.UNKNOWN, realName, null, SourceType.IMPORTED);
            } catch (Exception e) {
                Msg.info(this, "Unable to add function: " + function.getName() +
                                   " " + e);
                return false;
            }
            f.setThunkedFunction(extLoc.getFunction());

            //
            // Check for known no-returns, they mess up the analysis.
            if (realName.matches("exit")) {
                f.setNoReturn(true);
            }
            if (realName.matches("abort")) {
                f.setNoReturn(true);
            }
            return true;
        }

        try {
            this.listing.createFunction(function.getName(), entryAddress, body,
                                        SourceType.IMPORTED);
        } catch (Exception e) {
            Msg.info(this,
                     "Unable to add function: " + function.getName() + " " + e);
            return false;
        }
        return true;
    }

    private boolean addCodeSymbol(Symbol symbol, long address,
                                  Namespace namespace) {
        String name = symbol.getName();
        if ((name == null) || name.isEmpty()) {
            return false;
        }
        Address symbolAddress = program.getImageBase().add(address);
        symbol.setAddress(address);
        SymbolTable symbolTable = program.getSymbolTable();
        try {
            symbolTable.createLabel(symbolAddress, name, namespace,
                                    SourceType.IMPORTED);
        } catch (InvalidInputException e) {
            Msg.error(this, "addCodeSymbol threw Invalid Input Exception " + e);
            return false;
        }
        return true;
    }

    //
    // Treat a data symbol differently than a code symbol
    // In this case the name doesn't really matter, what matters is
    // recognizing this as some number, maybe an address, anyway not code.
    //
    private boolean addDataSymbol(Symbol symbol, long symbolAddress,
                                  Namespace namespace) {
        Address symbolFullAddress = program.getImageBase().add(symbolAddress);
        int length = 1;
        try {
            // Taken from ELF loader:
            // If it is bigger than 8, just let it go through and create a
            // single undefined Otherwise this would create an array of
            // undefined, might get in the way
            // TODO: how to really handle something bigger.
            if (length > 8) {
                length = 1;
            }
            if (length == 0) {
                length = 1;
            }
            program.getListing().createData(
                symbolFullAddress, Undefined.getUndefinedDataType(length));
        } catch (CodeUnitInsertionException e) {
            Msg.info(this,
                     "possible data markup conflict at " + symbolFullAddress);
        } catch (DataTypeConflictException e) {
            throw new AssertException("unexpected", e);
        }
        return true;
    }

    private long sectionSizeFixups(Section section, byte[] byteIntervalBytes,
                                   long byteIntervalSize) {
        // Specxtial handling for section sizes:
        //  - The .plt.got section consists only of a jump, but ghidra does
        //    not recognize it as non-returning, and the disassembler
        //    tries to continue into bogus bytes. The fixup is to make
        //    sure the function ends at the jump.
        //
        Module module = GtirbLoader.ir.getModule();
        if ((module.getISA() == Module.ISA.X64) ||
            (module.getISA() == Module.ISA.X64)) {
            if (section.getName().matches(".plt.got")) {
                // 2-byte sections are just trailing bytes - delete
                // Otherwise just remove the 2 trailing bytes
                if (byteIntervalSize == 2) {
                    return 0;
                } else if ((byteIntervalSize % 8) == 0) {
                    return byteIntervalSize - 2;
                }
            }
        } else if (module.getISA() == Module.ISA.PPC32) {
            // can have all zeros in it - if so discard.
            boolean allZeros = true;
            for (byte b : byteIntervalBytes) {
                if (b != 0)
                    allZeros = false;
            }
            if (allZeros)
                return 0;
        }
        return byteIntervalSize;
    }

    private boolean addSectionBytes(Section section, MessageLog log,
                                    TaskMonitor monitor) {
        List<ByteInterval> byteIntervals = section.getByteIntervals();

        String permissions = " ";
        boolean isReadable = false;
        boolean isWritable = false;
        boolean isExecutable = false;
        for (Section.SectionFlag sectionFlag : section.getSectionFlags()) {
            if (sectionFlag == Section.SectionFlag.Readable) {
                isReadable = true;
                permissions = permissions.concat("-Read");
            } else if (sectionFlag == Section.SectionFlag.Writable) {
                isWritable = true;
                permissions = permissions.concat("-Write");
            } else if (sectionFlag == Section.SectionFlag.Executable) {
                isExecutable = true;
                permissions = permissions.concat("-Execute");
            }
        }
        for (ByteInterval byteInterval : byteIntervals) {
            if (!byteInterval.hasAddress()) {
                Msg.info(this, "Unable to load byteInterval in " +
                                   section.getName() + " (it has no address).");
                continue;
            }
            Long byteIntervalAddress = byteInterval.getAddress();
            long byteIntervalSize = byteInterval.getSize();
            String byteIntervalComment =
                "byte interval " +
                String.format(" [%08x - %08x] ", byteIntervalAddress,
                              (byteIntervalAddress + byteIntervalSize - 1)) +
                permissions;
            Address loadAddress =
                program.getImageBase().add(byteIntervalAddress);
            byte[] byteArray =
                com.grammatech.gtirb.Util.toByteArray(byteInterval.getBytes());
            if (byteArray == null) {
                Msg.info(this, "Unable to load byteInterval "
                                   + "in " + section.getName() +
                                   " (byteArray is empty).");
                continue;
            }
            InputStream dataInput = new ByteArrayInputStream(byteArray);

            // Allow for fixups to byte interval
            byteIntervalSize =
                sectionSizeFixups(section, byteArray, byteIntervalSize);

            if (byteIntervalSize <= 0) {
                continue;
            }
            try {
                MemoryBlockUtils.createInitializedBlock(
                    program, false, section.getName(), loadAddress, dataInput,
                    byteIntervalSize, byteIntervalComment, "GTIRB Loader",
                    isReadable, isWritable, isExecutable, log, monitor);
            } catch (AddressOverflowException e) {
                Msg.error(this, "Address Overflow Exception. " + e);
                return false;
            }
            if (isExecutable) {
                for (Block block : byteInterval.getBlockList()) {
                    CodeBlock codeBlock = block.getCodeBlock();
                    if (codeBlock != null) {
                        long codeBlockAddress =
                            byteIntervalAddress + codeBlock.getOffset();
                        long codeBlockSize = codeBlock.getSize();
                        // No need to add offset, markAsCode handles that
                        markAsCode(codeBlockAddress, codeBlockSize);
                    }
                }
            }
        }
        return true;
    }

    private boolean doRelocation(long relocAddr, long relocValue) {
        // subtract image base, otherwise it is doubled
        // long targetAddr = relocAddr - this.loadOffset;
        try {
            this.memory.setLong(this.program.getImageBase().add(relocAddr),
                                relocValue);
        } catch (MemoryAccessException e) {
            Msg.error(this, "Unable to set do relocation " + e);
            return false;
        }
        return true;
    }

    // This only handles 64-bit (8 byte) word size currently
    // Needs looking at..
    // Must work for both endians, and for both 32 and 64 bit words.
    private boolean processRelocations(ArrayList<Section> sections,
                                       long fakeExternalBlockAddress,
                                       TaskMonitor monitor, MessageLog log) {
        long dynamicSymbolAddress = fakeExternalBlockAddress;
        for (Section section : sections) {
            String sectionName = section.getName();
            if (sectionName.equals(".dynsym")) {
                List<ByteInterval> byteIntervals = section.getByteIntervals();
                ByteInterval byteInterval = byteIntervals.get(0);

                Serialization serialization =
                    new Serialization(byteInterval.getBytesDirect());
                while (serialization.getRemaining() > 0) {
                    int symbolNameIndex = serialization.getInt();
                    byte symbolInfo = serialization.getByte();
                    byte symbolOther = serialization.getByte();
                    short symbolShndx = serialization.getShort();
                    long symbolValue = serialization.getLong();
                    long symbolSize = serialization.getLong();
                    String symbolName = byteArrayToString(dynStrSectionContents,
                                                          symbolNameIndex);
                    DynamicSymbol dynamicSymbol =
                        new DynamicSymbol(symbolName, symbolInfo, symbolOther,
                                          symbolShndx, symbolValue, symbolSize);
                    dynamicSymbols.add(dynamicSymbol);
                    dynamicSymbol.setAddr(dynamicSymbolAddress);
                    dynamicSymbolAddress += 8;
                }
            }
        }

        int sizeOfExternalSymbolBlock = (dynamicSymbols.size() * 8) + 16;

        // Create an uninitialized block of this size to point external
        // references to
        byte[] data = new byte[sizeOfExternalSymbolBlock];
        Arrays.fill(data, (byte)0x0); // (ret/retq)
        InputStream is = new ByteArrayInputStream(data);
        // subtract load offset, otherwise it is added twice!
        long externalOffset = fakeExternalBlockAddress - this.loadOffset;

        MemoryBlock externalBlock = null;
        try {
            externalBlock = MemoryBlockUtils.createInitializedBlock(
                program, false, "-external block-",
                this.program.getImageBase().add(externalOffset), is,
                sizeOfExternalSymbolBlock, "-external comment-",
                "-external source-", true, true, true, log, monitor);
        } catch (AddressOverflowException e) {
            Msg.error(this, "Create external memory block failed. " + e);
            return false;
        }
        if (externalBlock == null) {
            Msg.error(this, "Create external memory block failed.");
            return false;
        }

        for (ElfRelocation elfRelocation : elfRelocations) {
            DynamicSymbol relocationSymbol =
                dynamicSymbols.get(elfRelocation.getRelocSym());
            long relocAddr = elfRelocation.getRelocAddr();
            long relocAddend = elfRelocation.getRelocAddend();
            long symbolAddr = relocationSymbol.getAddr();

            // TODO: could verify reloc addr is valid for type and section
            // pointed to
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
                Msg.info(this, "Unhandled relocation " +
                                   elfRelocation.getRelocType().toString());
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
                flowType = (edge.isEdgeLabelConditional())
                               ? RefType.CONDITIONAL_JUMP
                               : RefType.UNCONDITIONAL_JUMP;
            } else if (edge.getEdgeType() == EdgeType.Type_Call) {
                flowType = (edge.isEdgeLabelConditional())
                               ? RefType.CONDITIONAL_CALL
                               : RefType.UNCONDITIONAL_CALL;
            } else if (edge.getEdgeType() == EdgeType.Type_Fallthrough) {
                flowType = RefType.FALL_THROUGH;
            } else {
                continue;
            }

            // Now do it.
            this.program.getReferenceManager().addMemoryReference(
                this.program.getImageBase().add(srcAddr),
                this.program.getImageBase().add(dstAddr), flowType,
                SourceType.IMPORTED, 0);
        }
        return true;
    }

    // Process symbol information
    //
    // A symbol is a label which also has an address, a symbol type and a source
    // type. This code adds all symbols as type CODE and source IMPORTED. Also
    // the addresses come from the gtirb referent UUID. See the gtirb data
    // symbols example code.
    //
    private boolean processSymbols(ArrayList<Symbol> symbols) {

        boolean isFakeExternal = false;

        // Create namespace for external symbols
        SymbolTable symbolTable = program.getSymbolTable();
        try {
            this.storageExtern = symbolTable.createNameSpace(
                // TODO FIXME TEN 7/29/20
                // null, Library.UNKNOWN, SourceType.IMPORTED);
                null, "<RELOC-REFS>", SourceType.IMPORTED);
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

            // If no payload, search the fake externals list for an assigned
            // address
            UUID referentUuid = symbol.getReferentByUuid();
            if (referentUuid.equals(com.grammatech.gtirb.Util.NIL_UUID)) {
                for (DynamicSymbol dynamicSymbol : this.dynamicSymbols) {
                    if (dynamicSymbol.getName().equals(symbol.getName())) {
                        // Add fakeExternal symbol
                        long symbolOffset =
                            dynamicSymbol.getAddr() - this.loadOffset;
                        addCodeSymbol(symbol, symbolOffset, this.storageExtern);
                        isFakeExternal = true;
                        break;
                    }
                }
                if (isFakeExternal == false) {
                    if (functionMap.containsKey("__thunk_" +
                                                symbol.getName())) {
                    } else {
                        // Not a function, external reference, or relocated
                        // symbol. This might be a sign of a problem.
                        Msg.info(
                            this,
                            "Symbol has no referrent and is not external, could not determine address: " +
                                symbol.getName());
                    }
                }
                continue;
            }
            Node referent = Node.getByUuid(referentUuid);
            if (referent == null) {
                continue;
            } else if (referent instanceof CodeBlock) {
                CodeBlock codeBlock = (CodeBlock)referent;
                long symbolOffset =
                    codeBlock.getBlock().getByteInterval().getAddress() +
                    codeBlock.getOffset();
                addCodeSymbol(symbol, symbolOffset, null);
            } else if (referent instanceof DataBlock) {
                DataBlock dataBlock = (DataBlock)referent;
                long symbolOffset =
                    dataBlock.getBlock().getByteInterval().getAddress() +
                    dataBlock.getOffset();
                addDataSymbol(symbol, symbolOffset, null);
            } else {
                for (DynamicSymbol dynamicSymbol : this.dynamicSymbols) {
                    if (dynamicSymbol.getName().equals(symbol.getName())) {
                        long symbolOffset =
                            dynamicSymbol.getAddr() - this.loadOffset;
                        addCodeSymbol(symbol, symbolOffset, this.storageExtern);
                        isFakeExternal = true;
                        break;
                    }
                }
                if (isFakeExternal == false) {
                    Msg.info(this, "Unable to determine symbol address: " +
                                       symbol.getName());
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
            CodeBlock codeBlock = (CodeBlock)uuidNode;
            return (codeBlock.getBlock().getByteInterval().getAddress() +
                    codeBlock.getOffset());
        } else if (uuidNode instanceof DataBlock) {
            DataBlock dataBlock = (DataBlock)uuidNode;
            return (dataBlock.getBlock().getByteInterval().getAddress() +
                    dataBlock.getOffset());
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
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider)
        throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // Map supported GTIRB ISAs to ELF e_machine value
        Map<Module.ISA, String> machineMap = Map.ofEntries(
            Map.entry(Module.ISA.IA32, "3"), Map.entry(Module.ISA.PPC32, "20"),
            Map.entry(Module.ISA.ARM, "40"), Map.entry(Module.ISA.X64, "62"));

        Map<Module.ISA, Integer> sizeMap = Map.ofEntries(
            Map.entry(Module.ISA.IA32, 32), Map.entry(Module.ISA.PPC32, 32),
            Map.entry(Module.ISA.ARM, 32), Map.entry(Module.ISA.X64, 64));

        Map<Module.ISA, Endian> endianMap =
            Map.ofEntries(Map.entry(Module.ISA.IA32, Endian.LITTLE),
                          Map.entry(Module.ISA.PPC32, Endian.BIG),
                          Map.entry(Module.ISA.ARM, Endian.LITTLE),
                          Map.entry(Module.ISA.X64, Endian.LITTLE));

        // IF the file ends with .gtirb, we will proceed, otherwise return an
        // empty list
        //   IFF we can load the gtirb file, examine the contents
        //      - What is ISA and what id FileFormat?
        //        IFF fileFormat is ELF, proceed to get language string
        //        - Pretend to be the ELF loader, and do a query
        //        - Go through all language strings returned, look for matches,
        //        and put in list
        String path = provider.getAbsolutePath();
        if (path.endsWith(GtirbConstants.GTIRB_EXTENSION)) {
            //
            // Load the GTIRB file into the IR
            // TODO: Make IR a class level object so that it won't have to be
            // re-loaded later
            //    (OR come up with a shortcut way of getting ISA and FileFormat
            //    so
            // that loading isn't needed here)
            //
            InputStream fileIn = provider.getInputStream(0);
            GtirbLoader.ir = IR.loadFile(fileIn);
            if (GtirbLoader.ir == null) {
                Msg.error(this, "GTIRB file load failed.");
            } else {

                Module module = GtirbLoader.ir.getModule();
                if (module.getFileFormat() != Module.FileFormat.ELF) {
                    Msg.error(
                        this,
                        "GTIRB file import failed (does not appear to be an ELF file).");
                } else {

                    if (machineMap.containsKey(module.getISA())) {
                        List<QueryResult> results = QueryOpinionService.query(
                            ElfLoader.ELF_NAME, machineMap.get(module.getISA()),
                            "0");

                        for (QueryResult result : results) {
                            boolean add = true;

                            // Check word size
                            if (sizeMap.get(module.getISA()) !=
                                result.pair.getLanguageDescription()
                                    .getSize()) {
                                add = false;
                            }
                            // Check endian
                            if (endianMap.get(module.getISA()) !=
                                result.pair.getLanguageDescription()
                                    .getEndian()) {
                                add = false;
                            }

                            if (add) {
                                loadSpecs.add(new LoadSpec(this, 0, result));
                            }
                        }
                    }
                }
            }
        }
        // Constructs an "unknown" compiler/language spec.
        // TODO do not know what use this at all. Remove?
        if (loadSpecs.isEmpty()) {
            loadSpecs.add(new LoadSpec(this, 0, true));
        }
        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec,
                        List<Option> options, Program program,
                        TaskMonitor monitor, MessageLog log)
        throws CancelledException, IOException {

        monitor.setMessage("Loading GTIRB ...");
        program.setExecutableFormat(GtirbLoader.GTIRB_NAME);
        this.program = program;
        this.memory = program.getMemory();
        this.listing = program.getListing();
        this.options = options;
        this.monitor = monitor;

        //
        // Load the GTIRB file into the IR
        //
        if (GtirbLoader.ir == null) {
            Msg.error(this, "GTIRB file load failed, unable to proceed.");
            return;
        }

        //
        // TODO: The operations that follow should be done per module.
        // For the moment only the first module is getting loaded.
        Module module = GtirbLoader.ir.getModule();

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
            // This is generally a list with only one item. If there are
            // multiple the last one is used.
            for (String binaryType : binaryTypeList) {
                Msg.info(this, "Module type:    " + binaryType);
                elfFileType = binaryType;
            }
        } else {
            Msg.info(this, "Module type defaulting to EXEC");
        }
        if (!setImageBase(elfFileType, program)) {
            Msg.error(this, "Failed to set image base address.");
            // if this fails, no alternative but to exit loader.
            return;
        }

        //
        // Process ELF Sections
        //
        // First get elfSectionProperties from auxData, setting flags and type
        // in the Gtirb section objects. Then iterate through the sections to:
        // - Add bytes from the Gtirb section into the program listing
        // - Determine the end of the loaded image (max address) so that a
        // "fake"
        //   external block can be placed after to the program, to resolve
        //   external references
        monitor.setMessage("Processing program sections...");
        Map<UUID, ArrayList<Long>> elfSectionProperties =
            module.getAuxData().getElfSectionProperties();
        if (elfSectionProperties != null) {
            processElfSectionProperties(elfSectionProperties);
        }

        ArrayList<Section> sections = module.getSections();
        long maxAddress = 0L;
        for (Section section : sections) {

            boolean retval = addSectionBytes(section, log, monitor);
            if (retval != true) {
                Msg.error(this, "Failed to add section bytes.");
                return;
            }

            //
            // Get byte interval address information, to determine where to put
            // fakeExternal block
            //
            String sectionName = section.getName();
            List<ByteInterval> byteIntervals = section.getByteIntervals();
            // DONT Understand why this is get(0). This may not be the highest
            // address in the section!
            // ByteInterval byteInterval = byteIntervals.get(0);
            ByteInterval byteInterval =
                byteIntervals.get(byteIntervals.size() - 1);
            long lastAddr = byteInterval.getAddress() + byteInterval.getSize() +
                            this.loadOffset;
            if (lastAddr > maxAddress) {
                maxAddress = lastAddr;
            }

            //
            // If this is ".dynstr", store the contents, because we will need to
            // search for symbol names there
            // TODO: This should be determined from elfSectionProperties instead
            // of being a constant! In fact relocation sections do not always
            // have this name! Although elfSectionProperties aux data may not
            // always be there, if it is not, then no relocations can be done.
            // Only in elfSectionProperties aux data do you have section header
            // type and section flags information.
            if (sectionName.equals(".dynstr")) {
                dynStrSectionContents = byteInterval.getBytesDirect();
            }
        }

        //
        // Get function information from AuxData
        monitor.setMessage("Initializing function map...");
        if (!initializeFunctionMap(module)) {
            Msg.error(this, "Failed to initialize function map.");
            return;
        }

        // Process relocations
        monitor.setMessage("Processing relocations...");
        if (!processRelocations(sections, maxAddress + 8, monitor, log)) {
            Msg.error(this, "Failure processing relocations.");
            return;
        }

        // Process symbol information
        monitor.setMessage("Initializing symbol table...");
        if (!processSymbols(module.getSymbols())) {
            Msg.error(this, "Failure processing symbols.");
            return;
        }

        // Process GTIRB CFG
        CFG cfg = ir.getCfg();
        if (!processControlFlowGraph(cfg, module)) {
            Msg.error(this, "Failure processing control flow graph.");
            return;
        }

        //
        // Further TODOs:
        //     Import auxdata comments
        monitor.setMessage("Processing program comments...");
        Map<Offset, String> comments = module.getAuxData().getComments();
        if (comments != null) {
            for (Map.Entry<Offset, String> entry : comments.entrySet()) {
                Offset offset = entry.getKey();
                // Offset has a UUID and a displacement
                // In the case of a comment, the UUID should be the code/data
                // block that has the comment
                long commentAddress;
                Node blockNode = Node.getByUuid(offset.getElementId());
                if (blockNode instanceof CodeBlock) {
                    CodeBlock codeBlock = (CodeBlock)blockNode;
                    long byteIntervalAddress =
                        codeBlock.getBlock().getByteInterval().getAddress();
                    commentAddress = byteIntervalAddress +
                                     codeBlock.getOffset() +
                                     offset.getDisplacement();
                } else if (blockNode instanceof DataBlock) {
                    DataBlock dataBlock = (DataBlock)blockNode;
                    long byteIntervalAddress =
                        dataBlock.getBlock().getByteInterval().getAddress();
                    commentAddress = byteIntervalAddress +
                                     dataBlock.getOffset() +
                                     offset.getDisplacement();
                } else {
                    continue;
                }
                Address ghidraAddress =
                    program.getImageBase().add(commentAddress);
                program.getListing().setComment(
                    ghidraAddress, CodeUnit.PRE_COMMENT, entry.getValue());
            }
        }
    }

    @Override
    public List<Option>
    getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
                      DomainObject domainObject, boolean isLoadIntoProgram) {
        List<Option> list = super.getDefaultOptions(
            provider, loadSpec, domainObject, isLoadIntoProgram);

        try {
            GtirbLoaderOptionsFactory.addOptions(list, provider, loadSpec);
        } catch (Exception e) {
            Msg.error(this, "Error while generating GTIRB import options", e);
            // ignore here, will catch later
        }

        return list;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec,
                                  List<Option> options, Program program) {

        // TODO: If this loader has custom options, validate them here.  Not all
        // options require validation.

        return super.validateOptions(provider, loadSpec, options, program);
    }

    public FileBytes getFileBytes() { return fileBytes; }

    public void setFileBytes(FileBytes fileBytes) {
        this.fileBytes = fileBytes;
    }

    public Listing getListing() { return listing; }

    public void setListing(Listing listing) { this.listing = listing; }

    public Memory getMemory() { return memory; }

    public void setMemory(Memory memory) { this.memory = memory; }
}

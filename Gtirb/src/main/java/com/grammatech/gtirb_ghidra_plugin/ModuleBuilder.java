/*
 *  Copyright (C) 2021 GrammaTech, Inc.
 *
 *  This code is licensed under the MIT license. See the LICENSE file in the
 *  project root for license terms.
 *
 */
package com.grammatech.gtirb_ghidra_plugin;

import com.grammatech.gtirb.*;
import com.grammatech.gtirb.Module;
import ghidra.app.util.exporter.ExporterException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;

import java.util.*;

/** Export handling to generate a GTIRB ${@link Module} based on the current state of Ghidra's ${@link Program}. */
public class ModuleBuilder {
    private final Program program;
    private final boolean enableDebugMessages = false;

    public ModuleBuilder(Program program) {
        this.program = program;
    }

    // TODO remove this when API's Node.getByUuid is fixed
    private HashMap<UUID, Node> nodeMap;
    private void populateNodeMap(Module module) {
        nodeMap = new HashMap<>();
        for (Section section : module.getSections()) {
            nodeMap.put(section.getUuid(), section);
            for (ByteInterval byteInterval : section.getByteIntervals()) {
                nodeMap.put(byteInterval.getUuid(), byteInterval);
                for (ByteBlock byteBlock : byteInterval.getBlockList()) {
                    nodeMap.put(byteBlock.getUuid(), byteBlock);
                }
            }
        }
        for (ProxyBlock proxyBlock : module.getProxyBlocks()) {
            nodeMap.put(proxyBlock.getUuid(), proxyBlock);
        }
        for (Symbol symbol : module.getSymbols()) {
            nodeMap.put(symbol.getUuid(), symbol);
        }
    }

    /** Get a block that starts at the specified address, splitting to make a new block if necessary. */
    public static UUID splitBlocksAtOffset(Module module, long offset, boolean forceExec, long sizeHint) {
        Section section = null;
        ByteInterval byteInterval = null;
        long newBlockOffset = 0;

        // Find the ByteInterval for this address
        for (Section curSection : module.getSections()) {
            for (ByteInterval curInterval : curSection.getByteIntervals()) {
                if (!curInterval.hasAddress())
                    continue;

                newBlockOffset = offset - curInterval.getAddress();
                if (newBlockOffset >= 0 && newBlockOffset < curInterval.getSize()) {
                    section = curSection;
                    byteInterval = curInterval;
                    break;
                }
            }
            if (byteInterval != null)
                break;
        }
        if (byteInterval == null)
            return null;

        boolean isExecutable = section.getSectionFlags().contains(Section.SectionFlag.Executable);
        if (forceExec && !isExecutable) {
            Msg.info(module, "Skipping non-executable CodeBlock: " +
                    section.getName() + " " + Long.toHexString(offset));
            return null;
        }

        // Find the matching block in this ByteInterval
        int blockIndex = 0;
        ByteBlock oldBlock = null;
        long oldBlockSize = 0;
        long oldBlockOffset = 0;
        for (ByteBlock block : byteInterval.getBlockList()) {
            long blockSize = block.getSize();
            oldBlockOffset = block.getOffset();

            // Block boundary matches what we need without splitting
            if (newBlockOffset == oldBlockOffset) {
                return block.getUuid();
            }

            // Check whether the new block should fill a gap between existing blocks
            if (newBlockOffset < oldBlockOffset) {
                break;
            }

            blockIndex++;

            // Check if this is the block we need to split
            if (newBlockOffset - oldBlockOffset < blockSize) {
                oldBlock = block;
                oldBlockSize = blockSize;
                break;
            }
        }

        // Split this block to make a new block that starts at the desired address
        ByteBlock newBlock;
        long newSize;
        long decodeMode = 0;
        if (oldBlock != null) {
            // Splitting an old block, keeping its offset but shrinking to fit a new block after it
            long prevSize = newBlockOffset - oldBlockOffset;
            newSize = oldBlockSize - prevSize;
            isExecutable = oldBlock instanceof CodeBlock;
            oldBlock.setSize(prevSize);
            if (isExecutable) {
                decodeMode = ((CodeBlock) oldBlock).getDecodeMode();
            }
        } else if (newBlockOffset >= oldBlockOffset) {
            // Adding a new block in empty space at the end of the ByteInterval.
            newSize = byteInterval.getSize() - newBlockOffset;
        } else {
            // Adding a new block in empty space. oldBlockOffset here refers to the *next* block.
            newSize = oldBlockOffset - newBlockOffset;
        }
        if (sizeHint > newSize) {
            // Ignore the size hint if we can't fit a block that large here
            Msg.info(module, "Unable to add a block that would overlap another block at "
            + section.getName() + ":" + Long.toHexString(newBlockOffset) + ".");
        } else if (sizeHint > 0) {
            newSize = sizeHint;
        }
        if (isExecutable) {
            newBlock = new CodeBlock(newSize, newBlockOffset, decodeMode, byteInterval);
        } else {
            newBlock = new DataBlock(newSize, newBlockOffset, byteInterval);
        }
        byteInterval.getBlockList().add(blockIndex, newBlock);

        return newBlock.getUuid();
    }

    /** Create a new Gtirb section based on the contents of a Ghidra memoryBlock. */
    private Section exportSection(Section section, MemoryBlock memoryBlock, Module module)
            throws ExporterException {
        if (section != null) {
            // TODO copy UUIDs from source Gtirb, but export everything else from memoryBlock
            return section;
        }

        String sectionName = memoryBlock.getName();
        ArrayList<Section.SectionFlag> sectionFlags = new ArrayList<>();
        ArrayList<ByteInterval> byteIntervals = new ArrayList<>();

        /* Gtirb also specifies a ThreadLocal section flag, but Ghidra doesn't have one here.
           Conversely, we aren't currently using Ghidra's isMapped, isOverlay, or isVolatile flags.
         */
        if (memoryBlock.isRead())
            sectionFlags.add(Section.SectionFlag.Readable);
        if (memoryBlock.isWrite())
            sectionFlags.add(Section.SectionFlag.Writable);
        if (memoryBlock.isExecute())
            sectionFlags.add(Section.SectionFlag.Executable);
        if (memoryBlock.isLoaded())
            sectionFlags.add(Section.SectionFlag.Loaded);
        if (memoryBlock.isInitialized())
            sectionFlags.add(Section.SectionFlag.Initialized);

        section = new Section(sectionName, sectionFlags, byteIntervals, module);

        byte[] blockBytes = null;
        if (memoryBlock.isInitialized()) {
            try {
                blockBytes = new byte[(int) memoryBlock.getSize()];
                memoryBlock.getBytes(memoryBlock.getStart(), blockBytes);
            } catch (MemoryAccessException e) {
                throw new ExporterException("Error reading section bytes: " + memoryBlock.getName());
            }
        }

        // TODO remove this hack when API is fixed
        if (blockBytes == null) {
            blockBytes = new byte[(int) memoryBlock.getSize()];
        }

        long biAddress = memoryBlock.getStart().getOffset() - program.getImageBase().getOffset();
        ByteInterval byteInterval = new ByteInterval(blockBytes, biAddress, section);
        byteInterval.setSize(memoryBlock.getSize());
        byteIntervals.add(byteInterval);

        return section;
    }

    //
    // exportComments
    //
    private Comments exportComments(Module module) {
        Listing listing = this.program.getListing();
        Memory memory = this.program.getMemory();
        AddressIterator addressIterator;

        Map<Long, ByteBlock> addrToBlockMap = GtirbUtil.getAddrToBlockMap(module);
        Map<Offset, String> commentMap = new HashMap<>();

        addressIterator = listing.getCommentAddressIterator(memory, true);
        while (addressIterator.hasNext()) {
            Address commentAddress = addressIterator.next();
            String commentString =
                    listing.getComment(CodeUnit.PRE_COMMENT, commentAddress);

            if (commentString != null) {
                long imageBase = this.program.getImageBase().getOffset();
                long longAddress = commentAddress.getOffset() - imageBase;
                ByteBlock block = addrToBlockMap.get(longAddress);
                if (block == null) {
                    continue;
                }

                long blockAddress = block.getAddress();
                long offset = longAddress - blockAddress;
                UUID uuid = block.getUuid();
                commentMap.put(new Offset(uuid, offset), commentString);
            }
        }
        return new Comments(commentMap);
    }

    /**
     * Get the address of a GTIRB symbol's referent.
     * @return An ImageBase-relative address, or 0 if the symbol has no referent in code or data.
     * */
    private Long getSymbolAddress(Symbol symbol) {
        long symbolOffset = 0;
        UUID referentUuid = symbol.getReferentByUuid();
        if (!referentUuid.equals(com.grammatech.gtirb.Util.NIL_UUID)) {
            Node symbolNode = nodeMap.get(symbol.getReferentByUuid());
            // Address here is really offset from image base
            // Only have address if code or data, anything else stays 0.
            if (symbolNode instanceof ByteBlock) {
                symbolOffset = ((ByteBlock) symbolNode).getAddress();
            } else {
                Msg.info(this, "Unable to get address of " + symbol.getName() +
                        ": referent is not a code or data block");
            }
        }
        return Long.valueOf(symbolOffset);
    }

    /** Creates a map of all symbols which existed in an imported GTIRB and have since been renamed. */
    private HashMap<String, String> findRenamedSymbols(ArrayList<Long> sharedAddresses,
                                                       HashMap<Long, Symbol> symbolIndex) {
        HashMap<String, String> renamedSymbols = new HashMap<String, String>();
        Long noAddress = program.getImageBase().getOffset();

        //
        // Iterate through all the Ghidra symbols, trying to
        // establish an address-based match of Ghidra and Gtirb symbols
        // If a match is found, and the names are different, it is a renaming.
        //
        for (ghidra.program.model.symbol.Symbol sym : program.getSymbolTable().getAllSymbols(true)) {

            Long symbolAddress = Long.valueOf(sym.getAddress().getOffset());

            //
            // Exclusions:
            // Do not proceed if the Ghidra symbols belongs to these
            // categories that are not allowed to rename:
            //  - Externals: Can't allow renaming of externals
            //  - Dynamics: Labels that Ghidra has and Gtirb does not
            //                TODO: Should try to export these to gtirb?
            //                What are they anyway?
            //  - Thunks: Generally this is a local redirection to a
            //                library function. Other kinds of thunks are
            //                possible, may need to revisit this.
            //  - No Address: Symbols for which no actual address has been
            //                assigned will have an address of 0 (or imageBase)
            //                These are not useful symbols to rename.
            //  - Shared addresses: Only symbols that have a unique
            //                address can be renamed, until support for UUID
            ///               has been added.
            //
            if (sym.isExternal()) {
                continue;
            } else if (sym.isDynamic()) {
                continue;
            } else if (sym.getSymbolType() == SymbolType.FUNCTION) {
                ghidra.program.model.listing.Function function =
                        this.program.getListing().getFunctionAt(sym.getAddress());
                if (function.isThunk()) {
                    continue;
                }
            } else if (symbolAddress.equals(noAddress)) {
                continue;
            } else if (sharedAddresses.contains(symbolAddress)) {
                continue;
            }

            if (symbolIndex.containsKey(symbolAddress)) {
                //
                // This symbol matches (by address) a Gtirb symbol, change name
                // if needed.
                //
                Symbol gtirbSymbol = symbolIndex.get(symbolAddress);
                if (!sym.getName().equals(gtirbSymbol.getName())) {
                    renamedSymbols.put(gtirbSymbol.getName(), sym.getName());
                    if (this.enableDebugMessages) {
                        Msg.info(this, sym.getName() + " was called " +
                                gtirbSymbol.getName() + ", adding to rename list");
                    }
                }
            } else {
                if (this.enableDebugMessages) {
                    Msg.info(this, sym.getName() + " : " + sym.getSymbolType() +
                            String.format(" @ %08x", symbolAddress) +
                            " does not match any Gtirb symbol.");
                }
            }
        }
        return renamedSymbols;
    }

    /**
     * Export the symbols that originally existed in the imported GTIRB, preserving the UUIDs
     * even if the symbol was renamed by the Ghidra user.
     * */
    // Strategy:
    //  - Start by creating a hashmap lookup table to match addresses with
    //    Gtirb symbols.
    //  - Iterate through the symbols in the Ghidra symbol table,
    //      - Look up each one by address to get the Gtirb-only things, such as
    //        UUID.
    //      - Build the new symbol using Symbol.newBuilder()
    //        using the Ghidra name regardless of whether it matches the Gtirb
    //        name.
    //      - Add the new symbol to newModule using addSymbols()
    //
    //  - Potential optimization: Could check if Ghidra symbols names match the
    //    ones imported from Gtirb, as it will be most of the time probably, and
    //    if they match just do a mergeFrom instead.
    //  - OR, iterate through GTIRB symbols, use getSymbolAt() to get Ghidra's
    //    name for that symbol, and use that in place of Gtirb name.
    //
    private void exportRenamedSymbols(Module module) {
        HashMap<String, String> renamedSymbols;
        ArrayList<Long> sharedAddresses = new ArrayList<>();
        // TODO not currently supporting adding new symbols.
        // addedSymbols.clear();

        // Get the program image base. All addresses are relative to this.
        long imageOffset = program.getImageBase().getOffset();

        // Null address for symbols that don't have one, like externals
        Long noAddress = imageOffset;
        populateNodeMap(module);

        // Create a hashmap with all the Gtirb symbols, indexed by address
        HashMap<Long, Symbol> symbolIndex = new HashMap<>();
        for (Symbol symbol : module.getSymbols()) {
            // Add the image base, these are gtirb addresses not load addresses.
            Long symbolAddress = getSymbolAddress(symbol) + imageOffset;
            if (symbolAddress.equals(noAddress)) {
                continue;
            }
            if (symbolIndex.containsKey(symbolAddress)) {
                // Symbols that don't have a unique address
                // just can't be renamed. In practice this
                // doesn't really matter.
                sharedAddresses.add(symbolAddress);
            } else {
                symbolIndex.put(symbolAddress, symbol);
            }
        }

        // Find all symbols that need to be renamed
        renamedSymbols = findRenamedSymbols(sharedAddresses, symbolIndex);

        //  Iterate through gtirb symbols, changing names if needed.
        ArrayList<Symbol> symbolList = new ArrayList<>();
        for (Symbol symbol : module.getSymbols()) {
            if (renamedSymbols.containsKey(symbol.getName())) {
                String oldName = symbol.getName();
                String newName = renamedSymbols.get(symbol.getName());
                if (oldName.startsWith(".") &&
                        oldName.substring(1).equals(newName)) {
                    // Don't rename if the only difference is a dot prefix,
                    // that leads to massive renaming
                } else {
                    symbol.setName(renamedSymbols.get(symbol.getName()));
                    Msg.info(this, "Renaming " + oldName + " to " + newName);
                }
            }
            symbolList.add(symbol);
        }
        module.setSymbols(symbolList);
    }

    /** Add Ghidra's symbols list to GTIRB. */
    private void exportSymbols(Module module) {
        ArrayList<Symbol> symbols = new ArrayList<>();
        for (ghidra.program.model.symbol.Symbol sym : program.getSymbolTable().getAllSymbols(false)) {
            Symbol gtSym = new Symbol(sym.getName(), module);
            gtSym.setUuid(UUID.randomUUID());

            UUID refUuid = null;
            if (!sym.isExternal()) {
                refUuid = splitBlocksAtOffset(module, sym.getAddress().subtract(program.getImageBase()),
                        false, 0);
            }
            if (refUuid != null)
                gtSym.setReferentByUuid(refUuid);
            symbols.add(gtSym);
        }
        module.setSymbols(symbols);
    }

    private CodeBlock getEntryPoint(Module module) {
        SymbolTable symbolTable = program.getSymbolTable();
        /* Ghidra standard loaders create an "entry" symbol for the entry point it gets from
         * the format header. This isn't perfect; it doesn't seem to work if the imported binary
         * already defines an "entry" symbol, but I can't find any other way in the Ghidra API to
         * get the entry point corresponding to ELF's e_entry, PE's AddressOfEntryPoint, etc.
         * This "entry" symbol seems to overwrite any existing entry point symbol, such as the
         * "_start" symbol that otherwise should exist for glibc programs.
         */
        for (ghidra.program.model.symbol.Symbol entrySym : symbolTable.getGlobalSymbols("entry")) {
            if (!entrySym.isExternalEntryPoint())
                continue;
            if (entrySym.getSymbolType() != SymbolType.FUNCTION)
                continue;
            for (Symbol symbol : module.getSymbols()) {
                if (symbol.getName().equals(entrySym.getName())) {
                    Node entryNode = symbol.getReferentUuid();
                    if (entryNode instanceof CodeBlock) {
                        return (CodeBlock) entryNode;
                    } else {
                        return null;
                    }
                }
            }
        }
        return null;
    }

    /** Populate a GTIRB Module from Ghidra's program data. */
    public Module exportModule(com.grammatech.gtirb.Module module) throws ExporterException {
        ProgramModule programModule = program.getListing().getDefaultRootModule();
        boolean isNewModule = false;

        // Export basic Module information
        if (module == null) {
            String fileFormatDesc = program.getExecutableFormat();
            LanguageDescription lang = program.getLanguage().getLanguageDescription();
            Module.FileFormat format;
            Module.ISA isa;

            isNewModule = true;

            isa = GtirbUtil.toISA(lang);
            format = GtirbUtil.toFileFormat(fileFormatDesc);

            if (isa == Module.ISA.ISA_Undefined) {
                throw new ExporterException("Unsupported processor: " + lang.getLanguageID());
            }
            if (format == Module.FileFormat.Format_Undefined) {
                /* It may be useful in the future to let this plugin export anything that Ghidra
                   was able to import. If we choose to support that, we probably should add the
                   LanguageID string to an AuxData schema for Ghidra-specific information. */
                throw new ExporterException("Unsupported source format: " + fileFormatDesc);
            }

            /* Current GTIRB API requires a non-null CodeBlock for Module constructor,
             * but this will be replaced with setEntryPoint later. */
            CodeBlock dummyCB = new CodeBlock(0, 0, 0, null);

            module = new Module(
                    program.getExecutablePath(),
                    program.getImageBase().getOffset(),
                    0, format, isa,
                    program.getName(),
                    null, null, null,
                    dummyCB,
                    null
            );
            //module.setName(program.getName());
            //module.setBinaryPath(program.getExecutablePath());
            //module.setPreferredAddr(program.getImageBase().getOffset());
            //module.setRebaseDelta(0);
            //module.setFileFormat(format);
            //module.setIsa(isa);
            module.setByteOrder(program.getLanguage().isBigEndian() ?
                    Module.ByteOrder.BigEndian : Module.ByteOrder.LittleEndian);
        }

        // Export sections
        ArrayList<Section> sectionList = new ArrayList<>();
        if (!isNewModule) {
            for (Section section : module.getSections()) {
                MemoryBlock memoryBlock = program.getMemory().getBlock(section.getName());
                sectionList.add(exportSection(section, memoryBlock, module));
            }
        } else {
            for (Group group : programModule.getChildren()) {
                MemoryBlock memoryBlock = program.getMemory().getBlock(group.getName());
                if (memoryBlock.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME)) {
                    continue;
                }
                sectionList.add(exportSection(null, memoryBlock, module));
            }
        }
        module.setSections(sectionList);

        // Export symbols
        if (isNewModule) {
            exportSymbols(module);
            module.setEntryPoint(getEntryPoint(module));
        } else {
            exportRenamedSymbols(module);
        }

        boolean alreadyHasComments = module.getAuxDataMap().containsKey("comments");
        if (!alreadyHasComments) {
            module.setComments(exportComments(module));
        }

        return module;
    }
}

/*
 *  Copyright (C) 2021 GrammaTech, Inc.
 *
 *  This code is licensed under the MIT license. See the LICENSE file in the
 *  project root for license terms.
 *
 */
package com.grammatech.gtirb_ghidra_plugin;

import com.google.protobuf.ByteString;
import com.grammatech.gtirb.*;
import com.grammatech.gtirb.Module;
import com.grammatech.gtirb.proto.*;
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

import java.nio.charset.StandardCharsets;
import java.util.*;

/** Export handling to generate a GTIRB ${@link Module} based on the current state of Ghidra's ${@link Program}. */
public class ModuleBuilder {
    private Program program;
    private boolean enableDebugMessages = false;

    public ModuleBuilder(Program program) {
        this.program = program;
    }

    /** Get a block that starts at the specified address, splitting to make a new block if necessary. */
    public static ByteString splitBlocksAtOffset(ModuleOuterClass.Module.Builder module, long offset,
                                                 boolean forceExec, long sizeHint) {
        SectionOuterClass.Section.Builder section = null;
        ByteIntervalOuterClass.ByteInterval.Builder byteInterval = null;
        long newBlockOffset = 0;

        // Find the ByteInterval for this address
        for (SectionOuterClass.Section.Builder curSection : module.getSectionsBuilderList()) {
            for (ByteIntervalOuterClass.ByteInterval.Builder curInterval : curSection.getByteIntervalsBuilderList()) {
                if (!curInterval.getHasAddress())
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

        boolean isExecutable =
                section.getSectionFlagsList().contains(SectionOuterClass.SectionFlag.Executable);
        if (forceExec && !isExecutable) {
            Msg.info(module, "Skipping non-executable CodeBlock: " +
                    section.getName() + " " + Long.toHexString(offset));
            return null;
        }

        // Find the matching block in this ByteInterval
        List<ByteIntervalOuterClass.Block.Builder> blockList = byteInterval.getBlocksBuilderList();
        int blockIndex = 0;
        ByteIntervalOuterClass.Block.Builder oldBlock = null;
        long oldBlockSize = 0;
        long oldBlockOffset = 0;
        for (ByteIntervalOuterClass.Block.Builder block : blockList) {
            long blockSize = 0;
            ByteString uuid = null;
            if (block.getValueCase() == ByteIntervalOuterClass.Block.ValueCase.CODE) {
                CodeBlockOuterClass.CodeBlock.Builder codeBlock = block.getCodeBuilder();
                blockSize = codeBlock.getSize();
                uuid = codeBlock.getUuid();
            } else {
                DataBlockOuterClass.DataBlock.Builder dataBlock = block.getDataBuilder();
                blockSize = dataBlock.getSize();
                uuid = dataBlock.getUuid();
            }
            oldBlockOffset = block.getOffset();

            // Block boundary matches what we need without splitting
            if (newBlockOffset == oldBlockOffset) {
                return uuid;
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
        ByteIntervalOuterClass.Block.Builder newBlock = ByteIntervalOuterClass.Block.newBuilder();
        long prevSize = 0;
        long newSize;
        ByteString newUuid = GtirbUtil.uuidGenByteString();
        if (oldBlock != null) {
            // Splitting an old block, keeping its offset but shrinking to fit a new block after it
            prevSize = newBlockOffset - oldBlockOffset;
            newSize = oldBlockSize - prevSize;
            isExecutable = oldBlock.getValueCase() == ByteIntervalOuterClass.Block.ValueCase.CODE;
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
            CodeBlockOuterClass.CodeBlock.Builder newCodeBlock = CodeBlockOuterClass.CodeBlock.newBuilder();
            if (oldBlock != null)
                oldBlock.getCodeBuilder().setSize(prevSize);
            newCodeBlock.setUuid(newUuid);
            newCodeBlock.setSize(newSize);
            newBlock.setCode(newCodeBlock);
        } else {
            DataBlockOuterClass.DataBlock.Builder newDataBlock = DataBlockOuterClass.DataBlock.newBuilder();
            if (oldBlock != null)
                oldBlock.getDataBuilder().setSize(prevSize);
            newDataBlock.setUuid(newUuid);
            newDataBlock.setSize(newSize);
            newBlock.setData(newDataBlock);
        }
        newBlock.setOffset(newBlockOffset);
        byteInterval.addBlocks(blockIndex, newBlock);

        return newUuid;
    }

    /** Create a new Gtirb section based on the contents of a Ghidra memoryBlock. */
    private SectionOuterClass.Section.Builder exportSection(Section section, MemoryBlock memoryBlock)
            throws ExporterException {
        SectionOuterClass.Section.Builder newSection =
                SectionOuterClass.Section.newBuilder();
        if (section != null) {
            // TODO copy UUIDs from source Gtirb, but export everything else from memoryBlock
            SectionOuterClass.Section protoSection = section.getProtoSection();
            newSection.mergeFrom(protoSection);
        } else {
            newSection.setName(memoryBlock.getName());
            newSection.setUuid(GtirbUtil.uuidGenByteString());

            /* Gtirb also specifies a ThreadLocal section flag, but Ghidra doesn't have one here.
               Conversely, we aren't currently using Ghidra's isMapped, isOverlay, or isVolatile flags.
             */
            if (memoryBlock.isRead())
                newSection.addSectionFlags(SectionOuterClass.SectionFlag.Readable);
            if (memoryBlock.isWrite())
                newSection.addSectionFlags(SectionOuterClass.SectionFlag.Writable);
            if (memoryBlock.isExecute())
                newSection.addSectionFlags(SectionOuterClass.SectionFlag.Executable);
            if (memoryBlock.isLoaded())
                newSection.addSectionFlags(SectionOuterClass.SectionFlag.Loaded);
            if (memoryBlock.isInitialized())
                newSection.addSectionFlags(SectionOuterClass.SectionFlag.Initialized);

            ByteIntervalOuterClass.ByteInterval.Builder byteInterval =
                    ByteIntervalOuterClass.ByteInterval.newBuilder();
            byte[] blockBytes = null;
            if (memoryBlock.isInitialized()) {
                try {
                    blockBytes = new byte[(int) memoryBlock.getSize()];
                    memoryBlock.getBytes(memoryBlock.getStart(), blockBytes);
                } catch (MemoryAccessException e) {
                    throw new ExporterException("Error reading section bytes: " + memoryBlock.getName());
                }
            }
            byteInterval.setUuid(GtirbUtil.uuidGenByteString());
            byteInterval.setHasAddress(true);
            byteInterval.setAddress(memoryBlock.getStart().getOffset() - program.getImageBase().getOffset());
            byteInterval.setSize(memoryBlock.getSize());
            if (blockBytes != null)
                byteInterval.setContents(ByteString.copyFrom(blockBytes));
            newSection.addByteIntervals(byteInterval);
        }
        return newSection;
    }

    /** Create a new Gtirb ProxyBlock. */
    private ProxyBlockOuterClass.ProxyBlock.Builder
    exportProxyBlock(ProxyBlock proxyBlock) {
        ProxyBlockOuterClass.ProxyBlock.Builder newProxyBlock =
                ProxyBlockOuterClass.ProxyBlock.newBuilder();
        ProxyBlockOuterClass.ProxyBlock protoProxyBlock =
                proxyBlock.getProtoProxyBlock();
        newProxyBlock.mergeFrom(protoProxyBlock);
        return newProxyBlock;
    }

    //
    // exportComments
    //
    private AuxDataOuterClass.AuxData.Builder exportComments(AuxData auxData, Module module) {

        AuxDataOuterClass.AuxData.Builder newAuxData =
                AuxDataOuterClass.AuxData.newBuilder();
        Listing listing = this.program.getListing();
        Memory memory = this.program.getMemory();
        AddressIterator addressIterator =
                listing.getCommentAddressIterator(memory, true);

        // Find out how much to allocate for all comment string plus UUID and
        // displacement for each one
        int numberOfComments = 0;
        int totalAllocation = 0;
        int sizeOfLong = 8;
        while (addressIterator.hasNext()) {
            Address commentAddress = addressIterator.next();
            // Look only for PRE for comments:
            String comment =
                    listing.getComment(CodeUnit.PRE_COMMENT, commentAddress);
            if (comment != null) {
                // For each comment, allocate: space for the Offset, and for the
                // string itself The "Offset" is actually a UUID and an uint64,
                // total is size of 3 longs The string itself needs length of
                // bytes plus one long for storing the string size Thus for each
                // comment we need string byte length, plus 4 times size of long
                totalAllocation +=
                        comment.getBytes(StandardCharsets.UTF_8).length;
                totalAllocation += (4 * sizeOfLong);
                numberOfComments += 1;
            }
        }
        // Add room for the 1st item, which is the number of comments
        totalAllocation += sizeOfLong;

        byte[] newCommentBytes = new byte[totalAllocation];
        Serialization serialization = new Serialization(newCommentBytes);
        serialization.putLong(numberOfComments);

        // Run through the comments again, this time adding to the comment data
        addressIterator = listing.getCommentAddressIterator(memory, true);
        while (addressIterator.hasNext()) {
            Address commentAddress = addressIterator.next();
            String commentString =
                    listing.getComment(CodeUnit.PRE_COMMENT, commentAddress);

            if (commentString != null) {
                long imageBase = this.program.getImageBase().getOffset();
                long longAddress = commentAddress.getOffset() - imageBase;
                Block block = module.getBlockFromAddress(longAddress);
                if (block == null) {
                    continue;
                }
                // Now I need the block address so I can set the displacement to
                // be the difference between the block start and the comment
                // address Also need to UUID of the code or data block. Then I
                // can write them.
                Long blockAddress =
                        block.getByteInterval().getAddress() + block.getOffset();
                Long offset = longAddress - blockAddress;
                UUID uuid;
                if (block.getCodeBlock() != null) {
                    uuid = block.getCodeBlock().getUuid();
                } else if (block.getDataBlock() != null) {
                    uuid = block.getDataBlock().getUuid();
                } else {
                    uuid = com.grammatech.gtirb.Util.NIL_UUID;
                }
                serialization.putUuid(uuid);
                serialization.putLong(offset);
                serialization.putString(commentString);
            }
        }
        newAuxData.setData(ByteString.copyFrom(newCommentBytes));
        String typeName = "mapping<Offset,string>";
        newAuxData.setTypeNameBytes(ByteString.copyFromUtf8(typeName));
        return newAuxData;
    }

    /**
     * Get the address of a GTIRB symbol's referent.
     * @return An ImageBase-relative address, or 0 if the symbol has no referent in code or data.
     * */
    private Long getSymbolAddress(Symbol symbol) {
        long symbolOffset = 0;
        UUID referentUuid = symbol.getReferentByUuid();
        if (!referentUuid.equals(com.grammatech.gtirb.Util.NIL_UUID)) {
            Node symbolNode = Node.getByUuid(symbol.getReferentByUuid());
            // Address here is really offset from image base
            // Only have address if code or data, anything else stays 0.
            if (symbolNode instanceof com.grammatech.gtirb.CodeBlock) {
                com.grammatech.gtirb.CodeBlock codeBlock = (com.grammatech.gtirb.CodeBlock)symbolNode;
                symbolOffset =
                        codeBlock.getBlock().getByteInterval().getAddress() +
                                codeBlock.getOffset();
            } else if (symbolNode instanceof DataBlock) {
                DataBlock dataBlock = (DataBlock)symbolNode;
                symbolOffset =
                        dataBlock.getBlock().getByteInterval().getAddress() +
                                dataBlock.getOffset();
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
    private void exportRenamedSymbols(com.grammatech.gtirb.Module module,
                                      ModuleOuterClass.Module.Builder newModule) {
        HashMap<String, String> renamedSymbols;
        ArrayList<Long> sharedAddresses = new ArrayList<Long>();
        // TODO not currently supporting adding new symbols.
        // addedSymbols.clear();

        // Get the program image base. All addresses are relative to this.
        long imageOffset = program.getImageBase().getOffset();

        // Null address for symbols that don't have one, like externals
        Long noAddress = imageOffset;

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
        for (Symbol symbol : module.getSymbols()) {
            SymbolOuterClass.Symbol.Builder newSymbol =
                    SymbolOuterClass.Symbol.newBuilder();
            SymbolOuterClass.Symbol protoSymbol = symbol.getProtoSymbol();
            newSymbol.mergeFrom(protoSymbol);
            if (renamedSymbols.containsKey(symbol.getName())) {
                String oldName = symbol.getName();
                String newName = renamedSymbols.get(symbol.getName());
                if (oldName.startsWith(".") &&
                        oldName.substring(1).equals(newName)) {
                    // Don't rename if the only difference is a dot prefix,
                    // that leads to massive renaming
                } else {
                    newSymbol.setName(renamedSymbols.get(symbol.getName()));
                    Msg.info(this, "Renaming " + oldName + " to " + newName);
                }
            }
            newModule.addSymbols(newSymbol);
        }
    }

    /** Add Ghidra's symbols list to GTIRB. */
    private void exportSymbols(com.grammatech.gtirb.Module module,
                               ModuleOuterClass.Module.Builder newModule) {
        if (module != null) {
            exportRenamedSymbols(module, newModule);
            return;
        }

        for (ghidra.program.model.symbol.Symbol sym : program.getSymbolTable().getAllSymbols(false)) {
            SymbolOuterClass.Symbol.Builder gtSym = SymbolOuterClass.Symbol.newBuilder();
            ByteString refUuid = null;
            gtSym.setUuid(GtirbUtil.uuidGenByteString());
            gtSym.setName(sym.getName());
            gtSym.setAtEnd(false);
            if (!sym.isExternal()) {
                refUuid = splitBlocksAtOffset(newModule, sym.getAddress().subtract(program.getImageBase()),
                        false, 0);
            }
            if (refUuid != null)
                gtSym.setReferentUuid(refUuid);
            newModule.addSymbols(gtSym);
        }
    }

    //
    // exportAuxData
    //
    private AuxDataOuterClass.AuxData.Builder exportAuxData(AuxData auxData,
                                                            String auxDataType,
                                                            Module module) {
        if (auxDataType.equals("comments")) {
            return exportComments(auxData, module);
        }
        AuxDataOuterClass.AuxData.Builder newAuxData =
                AuxDataOuterClass.AuxData.newBuilder();
        AuxDataOuterClass.AuxData oldAuxData =
                auxData.getProtoAuxData(auxDataType);
        // The following accomplishes the same as mergeFrom.
        // Just trying it to be make sure I understand
        byte[] oldAuxDataBytes = oldAuxData.getData().toByteArray();
        newAuxData.setData(ByteString.copyFrom(oldAuxDataBytes));
        newAuxData.setTypeName(oldAuxData.getTypeName());
        return newAuxData;
    }

    private ByteString getEntryPointUUID(ModuleOuterClass.Module.Builder module) {
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
            for (SymbolOuterClass.Symbol symbol : module.getSymbolsList()) {
                if (symbol.getName().equals(entrySym.getName())) {
                    return symbol.getReferentUuid();
                }
            }
        }
        return null;
    }

    /** Populate a GTIRB Module from Ghidra's program data. */
    public ModuleOuterClass.Module.Builder
    exportModule(com.grammatech.gtirb.Module module) throws ExporterException {
        ModuleOuterClass.Module.Builder newModule =
                ModuleOuterClass.Module.newBuilder();
        ProgramModule programModule = program.getListing().getDefaultRootModule();

        // Export basic Module information
        if (module != null) {
            ModuleOuterClass.Module protoModule = module.getProtoModule();

            newModule.setName(module.getName());
            newModule.setUuid(protoModule.getUuid());
            newModule.setBinaryPath(protoModule.getBinaryPath());
            newModule.setPreferredAddr(protoModule.getPreferredAddr());
            newModule.setRebaseDelta(protoModule.getRebaseDelta());
            newModule.setFileFormat(protoModule.getFileFormat());
            newModule.setIsa(protoModule.getIsa());
            newModule.setEntryPoint(protoModule.getEntryPoint());
            newModule.setByteOrder(protoModule.getByteOrder());
        } else {
            String fileFormatDesc = program.getExecutableFormat();
            LanguageDescription lang = program.getLanguage().getLanguageDescription();
            ModuleOuterClass.FileFormat format;
            ModuleOuterClass.ISA isa;

            isa = ModuleOuterClass.ISA.forNumber(GtirbUtil.toISA(lang).ordinal());
            format = ModuleOuterClass.FileFormat.forNumber(GtirbUtil.toFileFormat(fileFormatDesc).ordinal());

            if (isa == ModuleOuterClass.ISA.ISA_Undefined) {
                throw new ExporterException("Unsupported processor: " + lang.getLanguageID());
            }
            if (format == ModuleOuterClass.FileFormat.Format_Undefined) {
                /* It may be useful in the future to let this plugin export anything that Ghidra
                   was able to import. If we choose to support that, we probably should add the
                   LanguageID string to an AuxData schema for Ghidra-specific information. */
                throw new ExporterException("Unsupported source format: " + fileFormatDesc);
            }

            newModule.setFileFormat(format);
            newModule.setUuid(GtirbUtil.uuidGenByteString());
            newModule.setName(program.getName());
            newModule.setBinaryPath(program.getExecutablePath());
            newModule.setPreferredAddr(program.getImageBase().getOffset());
            newModule.setRebaseDelta(0);
            newModule.setIsa(isa);
            newModule.setByteOrder(program.getLanguage().isBigEndian() ?
                    ModuleOuterClass.ByteOrder.BigEndian : ModuleOuterClass.ByteOrder.LittleEndian);
        }

        // Export sections
        if (module != null) {
            for (Section section : module.getSections()) {
                MemoryBlock memoryBlock = program.getMemory().getBlock(section.getName());
                newModule.addSections(exportSection(section, memoryBlock));
            }
        } else {
            for (Group group : programModule.getChildren()) {
                MemoryBlock memoryBlock = program.getMemory().getBlock(group.getName());
                if (memoryBlock.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME)) {
                    continue;
                }
                newModule.addSections(exportSection(null, memoryBlock));
            }
        }

        // Export symbols
        exportSymbols(module, newModule);
        if (module == null)
            newModule.setEntryPoint(getEntryPointUUID(newModule));

        if (module != null) {
            // export proxy blocks
            for (ProxyBlock proxyBlock : module.getProxyBlockList()) {
                ProxyBlockOuterClass.ProxyBlock.Builder newProxyBlock =
                        exportProxyBlock(proxyBlock);
                newModule.addProxies(newProxyBlock);
            }

            //
            // Special handling of comments here because that is first to be
            // implemented If AuxData (in original gtirb) already had comments,
            // comments will get exported But if it didn't (for example, added by
            // Ghidra), then comments have to be exported explicitly
            boolean alreadyHasComments = false;
            Set<String> auxDataTypes = module.getAuxData().getAuxDataTypes();
            for (String auxDataType : auxDataTypes) {
                if (auxDataType.equals("comments"))
                    alreadyHasComments = true;
                AuxDataOuterClass.AuxData.Builder newAuxData = exportAuxData(
                        module.getAuxData(), auxDataType, module);
                AuxDataOuterClass.AuxData builtAuxData = newAuxData.build();
                newModule.putAuxData(auxDataType, builtAuxData);
            }

            if (alreadyHasComments == false) {
                AuxDataOuterClass.AuxData.Builder newAuxData =
                        exportAuxData(module.getAuxData(), "comments", module);
                AuxDataOuterClass.AuxData builtAuxData = newAuxData.build();
                newModule.putAuxData("comments", builtAuxData);
            }
        }

        return newModule;
    }
}

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

import ghidra.app.util.*;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.google.protobuf.ByteString;
import com.grammatech.gtirb.AuxData;
import com.grammatech.gtirb.Block;
import com.grammatech.gtirb.CodeBlock;
import com.grammatech.gtirb.DataBlock;
import com.grammatech.gtirb.IR;
import com.grammatech.gtirb.ProxyBlock;
import com.grammatech.gtirb.Section;
import com.grammatech.gtirb.Serialization;
import com.grammatech.gtirb.Symbol;
import com.grammatech.gtirb.Module;
import com.grammatech.gtirb.Node;
import com.grammatech.gtirb.proto.AuxDataOuterClass;
import com.grammatech.gtirb.proto.CFGOuterClass;
import com.grammatech.gtirb.proto.IROuterClass;
import com.grammatech.gtirb.proto.ModuleOuterClass;
import com.grammatech.gtirb.proto.ProxyBlockOuterClass;
import com.grammatech.gtirb.proto.SectionOuterClass;
import com.grammatech.gtirb.proto.SymbolOuterClass;

/**
 * An {@link ExportLoader} for exporting programs to GrammaTech Intermediate
 * Representation for Binaries (GTIRB).
 */
public class GtirbExporter extends Exporter {

    private Program program;
    private HashMap<String, String> renamedSymbols = null;
    // Current renaming algorithm does not allow renaming of symbols
    //   that share addresses - because they can't be uniquely identified.
    private ArrayList<Long> sharedAddresses = null;
    // TODO not currently supporting adding new symbols.
    // private ArrayList<Symbol> addedSymbols = null;

    /** Exporter constructor. */
    public GtirbExporter() {
        // Name the exporter and associate a file extension with it
        super("GTIRB Exporter", "gtirb", null);

        renamedSymbols = new HashMap<String, String>();
        sharedAddresses = new ArrayList<Long>();
        // TODO not currently supporting adding new symbols.
        // addedSymbols = new ArrayList<Symbol>();
    }

    //
    // not used.
    //
    // This method just does a per-symbol mergeFrom, so that the exported
    // gtirb symbol is identical to the original.
    //
    // export(copy)Symbols
    //
    private boolean copySymbols(com.grammatech.gtirb.Module module,
                                ModuleOuterClass.Module.Builder newModule) {
        for (Symbol symbol : module.getSymbols()) {
            SymbolOuterClass.Symbol.Builder newSymbol =
                SymbolOuterClass.Symbol.newBuilder();
            SymbolOuterClass.Symbol protoSymbol = symbol.getProtoSymbol();
            newSymbol.mergeFrom(protoSymbol);
            newModule.addSymbols(newSymbol);
        }
        return true;
    }

    //
    // not used.
    //
    // I thought I would need to change elf symbol info auxdata
    // as part of supporting the exporting of symbol name changes.
    // Turns out the auxdata only references names indirectly, so
    // nothing to change. Keeping for future reference though.
    //
    // exportElfSymbolInfo: Update elfSymbolInfo AuxData
    // to include name changes and return an builder.
    //
    // This method is probably irrelevant, since this AuxData
    // refers to a symbol by UUID, it would only be needed if
    // I were _adding_ a symbol. But then I would need to make
    // up some of this, like ELF Section number.
    //
    private AuxDataOuterClass.AuxData.Builder
    exportElfSymbolInfo(AuxData auxData, Program program, Module module) {

        AuxDataOuterClass.AuxData.Builder newAuxData =
            AuxDataOuterClass.AuxData.newBuilder();
        AuxDataOuterClass.AuxData oldAuxData =
            auxData.getProtoAuxData("elfSymbolInfo");
        byte[] oldAuxDataBytes = oldAuxData.getData().toByteArray();
        Serialization oldSerialization = new Serialization(oldAuxDataBytes);

        // Calculate size of byte buffer to create:
        // - Use size of existing byte buffer, delta by net size change of
        // renames
        byte[] newAuxDataBytes = new byte[oldAuxDataBytes.length];
        Serialization newSerialization = new Serialization(newAuxDataBytes);

        // Serialize the number of symbolInfo items
        long numSymbolInfo = oldSerialization.getLong();
        newSerialization.putLong(numSymbolInfo);

        // Iterate through them and set new from old
        for (int i = 0; i < numSymbolInfo; i++) {
            // UUID
            newSerialization.putUuid(oldSerialization.getUuid());
            // Size (long)
            newSerialization.putLong(oldSerialization.getLong());
            // Type (string)
            newSerialization.putString(oldSerialization.getString());
            // Binding (string)
            newSerialization.putString(oldSerialization.getString());
            // Visibility (string)
            newSerialization.putString(oldSerialization.getString());
            // Section number (long)
            newSerialization.putLong(oldSerialization.getLong());
        }

        newAuxData.setData(ByteString.copyFrom(newAuxDataBytes));
        String typeName =
            "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>";
        newAuxData.setTypeNameBytes(ByteString.copyFromUtf8(typeName));
        return newAuxData;
    }

    //
    // exportSection
    //
    private SectionOuterClass.Section.Builder exportSection(Section section) {
        SectionOuterClass.Section.Builder newSection =
            SectionOuterClass.Section.newBuilder();
        SectionOuterClass.Section protoSection = section.getProtoSection();
        newSection.mergeFrom(protoSection);
        return (newSection);
    }

    //
    // exportProxyBlock
    //
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
    private AuxDataOuterClass.AuxData.Builder
    exportComments(AuxData auxData, Program program, Module module) {

        AuxDataOuterClass.AuxData.Builder newAuxData =
            AuxDataOuterClass.AuxData.newBuilder();
        Listing listing = program.getListing();
        Memory memory = program.getMemory();
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
                long imageBase = program.getImageBase().getOffset();
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

    private Long getSymbolAddress(Symbol symbol) {
        long symbolOffset = 0;
        UUID referentUuid = symbol.getReferentByUuid();
        if (!referentUuid.equals(com.grammatech.gtirb.Util.NIL_UUID)) {
            Node symbolNode = Node.getByUuid(symbol.getReferentByUuid());
            // Address here is really offset from image base
            // Only have address if code or data, anything else stays 0.
            if (symbolNode instanceof CodeBlock) {
                CodeBlock codeBlock = (CodeBlock)symbolNode;
                symbolOffset =
                    codeBlock.getBlock().getByteInterval().getAddress() +
                    codeBlock.getOffset();
            } else if (symbolNode instanceof DataBlock) {
                DataBlock dataBlock = (DataBlock)symbolNode;
                symbolOffset =
                    dataBlock.getBlock().getByteInterval().getAddress() +
                    dataBlock.getOffset();
            }
        }
        return new Long(symbolOffset);
    }

    //
    // exportSymbols
    //
    //
    // This will build proto versions of the entire list of symbols and add
    // to the module.
    // Strategy:
    //  - Start by creatng a hashmap lookup table to match addresses with
    //    Gtirb symbols.
    //  - Iterate through the sysmbols in the Ghidra symbol table,
    //      - Look up each one by address to get the Gtirb-only things, such as
    //      UUID.
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
    private boolean exportSymbols(com.grammatech.gtirb.Module module,
                                  ModuleOuterClass.Module.Builder newModule) {
        //
        // This routine creates the list of addded and renamed symbols.
        // If somehow these are not empty, clear them out
        renamedSymbols.clear();
        sharedAddresses.clear();
        // TODO not currently supporting adding new symbols.
        // addedSymbols.clear();

        //
        // Get the program image base. All addresses are relative to this.
        Address imageBase = program.getImageBase();
        long imageOffset = imageBase.getOffset();

        // Define a null address -
        // A symbols with this address doesn't really have an address
        // (externals for instance)
        Long noAddress = new Long(imageOffset);
        //
        // Create a hashmap with all the Gtirb symbols, indexed by address
        // Add the image base, otherwise you won;t get any matches.
        //
        HashMap<Long, Symbol> symbolIndex = new HashMap<>();
        // Msg.info(this, " ----- Initializing hashmap...");
        for (Symbol symbol : module.getSymbols()) {
            // Long symbolAddress = new Long(symbol.getAddress() + imageOffset);
            Long symbolAddress = getSymbolAddress(symbol) + imageOffset;
            if (symbolAddress.equals(noAddress)) {
                // Msg.info(this, " skipping symbol with no address: " +
                // symbol.getName() + " : " + symbol.getAddress());
                continue;
            }
            if (symbolIndex.containsKey(symbolAddress)) {
                // Msg.info(this, "Adding " + symbol.getName() + " : " +
                // String.format(" : %08x", symbolAddress) + " to
                // sharedAddresses");
                //        " - rejecting because address is shard by other
                //        symbols ");
                // If there is already a symbol add this address,
                // add the address to the shared address list, no symbol
                // can be renamed without a unique address
                sharedAddresses.add(symbolAddress);
            } else {
                // Msg.info(this, "Adding " + symbol.getName() + " : " +
                // String.format(" : %08x", symbolAddress) + " to symbolIndex");
                symbolIndex.put(symbolAddress, symbol);
            }
        }
        // Msg.info(this, " ----- Initializing done");

        //
        // Iterate through all the Ghidra symbols, trying to
        // estabish an address-based match of Ghidra and Gtirb symbols
        // If a match is found, and the names are different, it is a renaming.
        //
        SymbolIterator allSymbolIterator =
            this.program.getSymbolTable().getAllSymbols(true);
        while (allSymbolIterator.hasNext()) {
            ghidra.program.model.symbol.Symbol s = allSymbolIterator.next();

            Long symbolAddress = new Long(s.getAddress().getOffset());

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
            // Would look better a single compound if?
            if (s.isExternal()) {
                continue;
            } else if (s.isDynamic()) {
                continue;
            } else if (s.getSymbolType().toString().equals("Function")) {
                ghidra.program.model.listing.Function function =
                    this.program.getListing().getFunctionAt(s.getAddress());
                if (function.isThunk()) {
                    continue;
                }
            } else if (symbolAddress.equals(noAddress)) {
                continue;
            } else if (sharedAddresses.contains(symbolAddress)) {
                // Msg.info(this, s.getName() + " : " + String.format(" : %08x",
                // symbolAddress) +
                //        " - rejecting because address is shard by other
                //        symbols ");
                continue;
            }

            if (symbolIndex.containsKey(symbolAddress)) {
                //
                // This symbol matches (by address) a Gtirb symbol, change name
                // if needed.
                //
                Symbol gtirbSymbol = symbolIndex.get(symbolAddress);
                if (!s.getName().equals(gtirbSymbol.getName())) {
                    // Msg.info(this, s.getName() + " was called " +
                    // gtirbSymbol.getName() + ", adding to rename list");
                    renamedSymbols.put(gtirbSymbol.getName(), s.getName());
                }
            } else {
                Msg.info(this, s.getName() + " : " + s.getSymbolType() +
                                   String.format(" @ %08x", symbolAddress) +
                                   " does not match any Gtirb symbol.");
            }
        }
        //
        //  Iterate through gtirb symbols, changing names if needed.
        for (Symbol symbol : module.getSymbols()) {
            // Msg.info(this, " exporting " + symbol.getName());
            SymbolOuterClass.Symbol.Builder newSymbol =
                SymbolOuterClass.Symbol.newBuilder();
            SymbolOuterClass.Symbol protoSymbol = symbol.getProtoSymbol();
            newSymbol.mergeFrom(protoSymbol);
            if (renamedSymbols.containsKey(symbol.getName())) {
                String oldName = symbol.getName();
                String newName = renamedSymbols.get(symbol.getName());
                // Msg.info(this, " RENAMING " + symbol.getName() + " to " +
                // renamedSymbols.get(symbol.getName()));
                if (oldName.startsWith(".") &&
                    oldName.substring(1).equals(newName)) {
                    // Msg.info(this, " not renaming, it would just remove the
                    // initial period.");
                    ;
                } else {
                    Msg.info(this, " Renaming " + oldName + " to " + newName);
                    newSymbol.setName(renamedSymbols.get(symbol.getName()));
                }
            }
            newModule.addSymbols(newSymbol);
        }
        return true;
    }

    //
    // exportAuxData
    //
    private AuxDataOuterClass.AuxData.Builder exportAuxData(AuxData auxData,
                                                            String auxDataType,
                                                            Program program,
                                                            Module module) {
        if (auxDataType.equals("comments")) {
            return exportComments(auxData, program, module);
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

    //
    // exportModule()
    //
    // Have to avoid confusion with java.io.Module
    private ModuleOuterClass.Module.Builder
    exportModule(com.grammatech.gtirb.Module module, Program program) {
        ModuleOuterClass.Module.Builder newModule =
            ModuleOuterClass.Module.newBuilder();
        ModuleOuterClass.Module protoModule = module.getProtoModule();
        newModule.setUuid(protoModule.getUuid());
        newModule.setBinaryPath(protoModule.getBinaryPath());
        newModule.setPreferredAddr(protoModule.getPreferredAddr());
        newModule.setRebaseDelta(protoModule.getRebaseDelta());
        newModule.setFileFormat(protoModule.getFileFormat());
        newModule.setIsa(protoModule.getIsa());
        newModule.setEntryPoint(protoModule.getEntryPoint());
        newModule.setBinaryPath(protoModule.getBinaryPath());

        // export sections
        for (Section section : module.getSections()) {
            SectionOuterClass.Section.Builder newSection =
                exportSection(section);
            newModule.addSections(newSection);
        }

        // export symbols
        if (!exportSymbols(module, newModule)) {
            Msg.error(this, "Error exporting symbols");
        }

        // export proxy blocks
        for (ProxyBlock proxyBlock : module.getProxyBlockList()) {
            ProxyBlockOuterClass.ProxyBlock.Builder newProxyBlock =
                exportProxyBlock(proxyBlock);
            newModule.addProxies(newProxyBlock);
        }

        // export comments
        //
        // Special handling of comments here because that is first to be
        // implemented If auxdata (in original gtirb) already had comments,
        // comments will get exported But if it didn't (for example, added by
        // Ghidra), then comments have to be exported explicitely
        boolean alreadyHasComments = false;
        Set<String> auxDataTypes = module.getAuxData().getAuxDataTypes();
        for (String auxDataType : auxDataTypes) {
            if (auxDataType.equals("comments"))
                alreadyHasComments = true;
            AuxDataOuterClass.AuxData.Builder newAuxData = exportAuxData(
                module.getAuxData(), auxDataType, program, module);
            AuxDataOuterClass.AuxData builtAuxData = newAuxData.build();
            newModule.putAuxData(auxDataType, builtAuxData);
        }

        if (alreadyHasComments == false) {
            AuxDataOuterClass.AuxData.Builder newAuxData =
                exportAuxData(module.getAuxData(), "comments", program, module);
            AuxDataOuterClass.AuxData builtAuxData = newAuxData.build();
            newModule.putAuxData("comments", builtAuxData);
        }

        return newModule;
    }

    //
    // exportProgramToFile
    //
    private boolean exportProgramToFile(Program program, IR ir,
                                        OutputStream fileOut) {
        //
        // Start building a new IR
        IROuterClass.IR.Builder newIR = IROuterClass.IR.newBuilder();
        IROuterClass.IR protoIR = ir.getProtoIR();

        // IR has UUID, version, and AuxData.
        // Ignore AuxData for now, I've never seen an example of it at the top
        // level
        newIR.setUuid(protoIR.getUuid());
        newIR.setVersion(protoIR.getVersion());

        // Add the module
        ModuleOuterClass.Module.Builder newModule =
            exportModule(ir.getModule(), program);
        // Keep the same module name
        newModule.setName(ir.getModule().getName());
        newIR.addModules(newModule);

        // Add the CFG
        CFGOuterClass.CFG.Builder newCFG = ir.getCfg().buildCFG();
        newIR.setCfg(newCFG);

        try {
            newIR.build().writeTo(fileOut);
        } catch (Exception e) {
            Msg.error(this, "Exception writing file: " + e);
            return false;
        }
        return true;
    }

    //
    // export
    //
    @Override
    public boolean export(File file, DomainObject domainObj,
                          AddressSetView addrSet, TaskMonitor monitor)
        throws ExporterException, IOException {

        // 1. Get the program
        // (This method came from ASCII exporter)
        if (!(domainObj instanceof Program)) {
            log.appendMsg("Unsupported type: " +
                          domainObj.getClass().getName());
            return false;
        }
        this.program = (Program)domainObj;

        // 2. From program get file and open it
        String fileName = program.getExecutablePath();
        //
        // TODO: May want to reject an attempt to export a file that was not
        // originally GTIRB
        //       Or, if it is supported, use an alternate procedure.
        //

        // 3. Get the IR
        // It could be that the IR loaded by the loader is still around
        // (a load followed by an export for instance). If so, use it.
        // Otherwise we need to load the file.
        //
        // NOTE This means the original (GTIRB) file must still be around
        // for exporting to work.
        //
        IR ir = GtirbLoader.getIR();
        if (ir == null) {
            File inputFile = new File(fileName);
            InputStream inputStream;
            try {
                inputStream = new FileInputStream(inputFile);
            } catch (Exception e) {
                Msg.error(this, "Error opening file" + e);
                return false;
            }
            Msg.info(this, " -> IR was null, needed to load file.");
            ir = IR.loadFile(inputStream);
        }

        // 4. Open output file
        FileOutputStream fos = null;
        boolean retval = true;
        try {
            fos = new FileOutputStream(file);
        } catch (IOException ie) {
            Msg.error(this, "Error opening file" + ie);
            retval = false;
        }
        if (retval == false) {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException ioe) {
                    Msg.error(this, "Error closing file " + ioe);
                }
            }
            return false;
        }
        return (this.exportProgramToFile(program, ir, fos));
    }

    //
    // getOptions
    //
    @Override
    public List<Option> getOptions(DomainObjectService domainObjectService) {
        List<Option> list = new ArrayList<>();

        // TODO: If this exporter has custom options, add them to 'list'
        list.add(new Option("Option name goes here",
                            "Default option value goes here"));

        return list;
    }

    //
    // setOptions
    //
    @Override
    public void setOptions(List<Option> options) throws OptionException {

        // TODO: If this exporter has custom options, assign their values to the
        // exporter here
    }
}

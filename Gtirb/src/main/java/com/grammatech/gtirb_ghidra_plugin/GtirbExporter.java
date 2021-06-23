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

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.google.protobuf.ByteString;
import com.grammatech.gtirb.AuxData;
import com.grammatech.gtirb.Block;
import com.grammatech.gtirb.ByteInterval;
// NOTE: The name "CodeBlock" is used by both Ghidra and GTIRB, 
//       by commenting out this import I am choosing to import 
//       Ghidra CodeBlocks only, and so have to use full path 
//       when referring to GTIRB CodeBlocks.
//import com.grammatech.gtirb.CodeBlock;
import com.grammatech.gtirb.DataBlock;
import com.grammatech.gtirb.IR;
import com.grammatech.gtirb.Module;
import com.grammatech.gtirb.Node;
import com.grammatech.gtirb.ProxyBlock;
import com.grammatech.gtirb.Section;
import com.grammatech.gtirb.Serialization;
import com.grammatech.gtirb.Symbol;
import com.grammatech.gtirb.proto.AuxDataOuterClass;
import com.grammatech.gtirb.proto.CFGOuterClass;
import com.grammatech.gtirb.proto.IROuterClass;
import com.grammatech.gtirb.proto.ModuleOuterClass;
import com.grammatech.gtirb.proto.ProxyBlockOuterClass;
import com.grammatech.gtirb.proto.SectionOuterClass;
import com.grammatech.gtirb.proto.SymbolOuterClass;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * An {@link Exporter} for exporting programs to GrammaTech Intermediate
 * Representation for Binaries (GTIRB).
 */
public class GtirbExporter extends Exporter {

    //
    // Embedded class to represent edges 
    // (but "Edge" has already been used)
    private class Flow<S,T> {

        private final S source;
        private final T target;

        public Flow(S source, T target) {
            this.source = source;
            this.target = target;
        }

        public S getSource() { return source; }
        public T getTarget() { return target; }

        @Override
        public int hashCode() { return source.hashCode() ^ target.hashCode(); }

        @Override
        public boolean equals(Object a) {
            if (!(a instanceof Flow)) {
                return false;
            }
            Flow<?, ?> aflow = (Flow<?, ?>) a;
            return (this.source.equals(aflow.getSource()) &&
                    this.target.equals(aflow.getTarget()));
        }
    }
    
    private Program program;
    private HashMap<String, String> renamedSymbols = null;
    private ArrayList<Long> sharedAddresses = null;
    private HashMap<Long, UUID> addressToBlock = null;
    private boolean enableDebugMessages = false;

    /** Exporter constructor. */
    public GtirbExporter() {
        // Name the exporter and associate a file extension with it
        super("GTIRB Exporter", "gtirb", null);

        renamedSymbols = new HashMap<String, String>();
        addressToBlock = new HashMap<Long, UUID>();
        sharedAddresses = new ArrayList<Long>();
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
    exportComments(AuxData auxData, Module module) {

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

    //
    // getSymbolAddress
    //
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
                Msg.info(this, "Unable to get address of " + symbol.getName() + ": referent is not a code or data block");
            }
        }
        return Long.valueOf(symbolOffset);
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
        Long noAddress = Long.valueOf(imageOffset);
        //
        // Create a hashmap with all the Gtirb symbols, indexed by address
        // Add the image base, these are gtirb addresses not load addresses.
        //
        HashMap<Long, Symbol> symbolIndex = new HashMap<>();
        for (Symbol symbol : module.getSymbols()) {
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

        //
        // Iterate through all the Ghidra symbols, trying to
        // estabish an address-based match of Ghidra and Gtirb symbols
        // If a match is found, and the names are different, it is a renaming.
        //
        SymbolIterator allSymbolIterator =
            this.program.getSymbolTable().getAllSymbols(true);
        while (allSymbolIterator.hasNext()) {
            ghidra.program.model.symbol.Symbol s = allSymbolIterator.next();

            Long symbolAddress = Long.valueOf(s.getAddress().getOffset());

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
                continue;
            }

            if (symbolIndex.containsKey(symbolAddress)) {
                //
                // This symbol matches (by address) a Gtirb symbol, change name
                // if needed.
                //
                Symbol gtirbSymbol = symbolIndex.get(symbolAddress);
                if (!s.getName().equals(gtirbSymbol.getName())) {
                    renamedSymbols.put(gtirbSymbol.getName(), s.getName());
                    if (this.enableDebugMessages) {
                        Msg.info(this, s.getName() + " was called " +
                            gtirbSymbol.getName() + ", adding to rename list");
                    }
                }
            } else {
                if (this.enableDebugMessages) {
                    Msg.info(this, s.getName() + " : " + s.getSymbolType() +
                                   String.format(" @ %08x", symbolAddress) +
                                   " does not match any Gtirb symbol.");
                }
            }
        }
        //
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
        return true;
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

    //
    // exportModule()
    //
    // Have to avoid confusion with java.io.Module
    private ModuleOuterClass.Module.Builder
    exportModule(com.grammatech.gtirb.Module module) {
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

        return newModule;
    }


    // Should be moved to Util or somewhere that it can be shared.
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
        if (uuidNode instanceof com.grammatech.gtirb.CodeBlock) {
            com.grammatech.gtirb.CodeBlock codeBlock = (com.grammatech.gtirb.CodeBlock)uuidNode;
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


    //
    // initAddressToBlockMap
    // 
    // The address to block map is needed because edges are stored as UUID-UUID pairs,
    // (each UUID identifying a code blcok), while Ghidra considers an edge to be a pair
    // of addresses. Exporting CFG requires translating Ghidra edges to GTIRB
    // edges, and the most efficient way to get a block UUID from an address is to
    // create a map of addresses to blocks before starting the export.
    private boolean initAddressToBlockMap (Module module) {
        // for every block, add an entry in the address to block map
        // NOTE: Thises are Gtirb addresses, not load addresses.
        // TODO: Sorting by address would make this a much more 
        // efficient operaton.
        for (Section section : module.getSections()) {
            for (ByteInterval byteInterval : section.getByteIntervals()) {
                for (Block block : byteInterval.getBlockList()) {
                    com.grammatech.gtirb.CodeBlock codeBlock = block.getCodeBlock();
                    if (codeBlock != null) {
                        Long blockAddr = codeBlock.getBlock().getByteInterval().getAddress() + codeBlock.getOffset();
                        addressToBlock.put(blockAddr, codeBlock.getUuid());
                    }
                }
            }
        }
        return true;
    }

    // archival:
    // this is how to get an address for a block UUID
    //private Long addrFromUuid (UUID uuid) {
    //    Node node = Node.getByUuid(uuid);
    //    if (node instanceof com.grammatech.gtirb.CodeBlock) {
    //        com.grammatech.gtirb.CodeBlock codeBlock = (com.grammatech.gtirb.CodeBlock)node;
    //        Long blockAddress =
    //            codeBlock.getBlock().getByteInterval().getAddress() +
    //            codeBlock.getOffset();
    //        return (blockAddress);
    //    } else if (node instanceof com.grammatech.gtirb.DataBlock) {
    //        com.grammatech.gtirb.DataBlock dataBlock = (com.grammatech.gtirb.DataBlock)node;
    //        Long blockAddress =
    //            dataBlock.getBlock().getByteInterval().getAddress() +
    //            dataBlock.getOffset();
    //        return (blockAddress);
    //    } else {
    //        return (0L);
    //    }
    //}

    //
    // exportCFG
    //
    // private boolean exportCFG
    //
    // Procedure:
    // - Iterate through edges as in original GTIRB, add to output CFG
    // - Iterate through edges generated byCfgGhidra.java
    //   - If edge is not in output, and is not external, add to output CFG
    // How?
    // - Need ir, to get CFG
    // - Need module, to map edge UUID to block addresses (this can be retrieved from the ir)
    // - edge is source, dest, and type
    private CFGOuterClass.CFG.Builder exportCFG(IR ir, TaskMonitor monitor) {

        //
        // These are the edges in the original GTIRB, stored
        // as src-tgt only, so we can discriminate between added
        // and original edges.
        //HashMap<UUID, UUID> oldEdges = new HashMap<UUID, UUID>();
        ArrayList<Flow<UUID,UUID>> oldEdges = new ArrayList<Flow<UUID,UUID>>();

        //
        // create a new CFG
        CFGOuterClass.CFG.Builder newCFG = CFGOuterClass.CFG.newBuilder();

        //
        // Copy all edges from the original GTIRB to the new CFG
        List<com.grammatech.gtirb.proto.CFGOuterClass.Edge> protoEdges = ir.getProtoIR().getCfg().getEdgesList();
        for (com.grammatech.gtirb.proto.CFGOuterClass.Edge protoEdge : protoEdges) {
            CFGOuterClass.Edge.Builder newEdge = CFGOuterClass.Edge.newBuilder();
            newEdge.setLabel(protoEdge.getLabel())
                .setSourceUuid(protoEdge.getSourceUuid())
                .setTargetUuid(protoEdge.getTargetUuid());
            newCFG.addEdges(newEdge);

            UUID sourceUuid = com.grammatech.gtirb.Util.byteStringToUuid(protoEdge.getSourceUuid());
            UUID targetUuid = com.grammatech.gtirb.Util.byteStringToUuid(protoEdge.getTargetUuid());

            //Msg.info(this, "OLD EDGE (uuid): " + sourceUuid + " - " + targetUuid);
            //Msg.info(this, "OLD EDGE (addr):  0x" + Long.toHexString(addrFromUuid(sourceUuid)) +
            //            "    0x" + Long.toHexString(addrFromUuid(targetUuid)) +
            //            "    " + protoEdge.getLabel().getType().toString());

            Flow<UUID, UUID> flow = new Flow<UUID, UUID>(sourceUuid, targetUuid);
            oldEdges.add(flow);
        }

        // 
        //  Initialize an address-to-block UUID look up table
        if (initAddressToBlockMap(ir.getModule()) != true) {
            Msg.error(this, "Export CFG: Failed to initialize address-to-block look up");
            return (newCFG);   
        }

        //
        // Check out the edges that ghidra has.
        // This is a two pass operation
        // First pass is needed to collect the references from each code block
        //
        //      (this is needed because ghidra blocks have destinations that are not
        //       and/or not in the list of references from the block. I'm not sure
        //       what these destinations are supposed to represent, they seem
        //       extraneous. But the reference manager gives a list of references
        //       that more or less match what GTIRB calls edges.)
        //
        // NOTE: These are all load addresses, subtract imageBase to compare with GTIRB
        // NOTE: Ghidra does not show returns in any case, which is different from GTIRB.
        //       That is, in GTIRB, a RET would generate an edge to a callsite, Ghidra 
        //       does not do this.
        // TODO: Allow new edges to externals?
        boolean includeExternals = false;
        long imageBase = this.program.getImageBase().getOffset();
        BasicBlockModel basicBlockModel = new BasicBlockModel(this.program, includeExternals); 
        ReferenceManager referenceManager = this.program.getReferenceManager();
        List<Long> validBlocks = new ArrayList<Long>();
        try {
            CodeBlockIterator codeBlockIterator = basicBlockModel.getCodeBlocks(monitor);
            // NOTE: These are Ghidra CodeBlocks thus do not need to be qualified
            while (codeBlockIterator.hasNext()) {
                CodeBlock codeBlock = codeBlockIterator.next();
                //
                // A code block with no destinations may be something that needs special handling
                // Here I just let it pass.
                if (codeBlock.getNumDestinations(monitor) != 0) {
                    Reference[] fromReferences = referenceManager.getFlowReferencesFrom(codeBlock.getFirstStartAddress());
                    for (Reference reference : fromReferences) {
                        Long validSource = reference.getFromAddress().getOffset();
                        if (!validBlocks.contains(validSource)) {
                            validBlocks.add(validSource);
                        }
                        Long validDestination = reference.getToAddress().getOffset() - imageBase;
                        if (!validBlocks.contains(validDestination)) {
                            validBlocks.add(validDestination);
                        }
                    }
                }
            }
        } catch (Exception e) {
                Msg.error(this, "Export CFG: Exception iterating through blocks (first pass): " + e);
            return(newCFG);
        }
        //
        // Second pass to generate the valid set of edges
        try {
            CodeBlockIterator codeBlockIterator = basicBlockModel.getCodeBlocks(monitor);
            codeBlockIterator = basicBlockModel.getCodeBlocks(monitor);
            // NOTE: These are Ghidra CodeBlocks thus do not need to be qualified
            while (codeBlockIterator.hasNext()) {
                CodeBlock codeBlock = codeBlockIterator.next();
                Long startAddress = codeBlock.getFirstStartAddress().getOffset() - imageBase;
                if (!validBlocks.contains(startAddress)) {
                    continue;
                }
                UUID srcUuid = addressToBlock.get(startAddress);
                if (srcUuid == null) {
                    // This shouldn't happen normally:
                    Msg.info(this, "Export CFG: Source address does not map to a code block: 0x"
                                        + Long.toHexString(startAddress));
                    continue;
                } 
                Reference[] fromReferences = referenceManager.getFlowReferencesFrom(codeBlock.getFirstStartAddress());
                for (Reference reference : fromReferences) {
                    Long destinationAddress = reference.getToAddress().getOffset() - imageBase;

                    //
                    // So now we have an edge, but is it a NEW edge?
                    UUID dstUuid = addressToBlock.get(destinationAddress);
                    if (dstUuid == null) {
                        if (this.enableDebugMessages) {
                            // But, it's normal for external calls to hit this condition:
                            Msg.info(this, "Export CFG: Destination address does not map to a code block: 0x"
                                            + Long.toHexString(destinationAddress));
                        }
                        continue;
                    } 

                    Flow<UUID, UUID> flow = new Flow<UUID, UUID>(srcUuid, dstUuid);
             
                    if (oldEdges.contains(flow)) {
                        //Msg.info(this, "Export CFG: GTIRB and Ghidra edge match: " + Long.toHexString(startAddress) +
                        //            "    0x" + Long.toHexString(destinationAddress) +
                        //            "    " + reference.getReferenceType().toString());
                        continue;
                    } else {
                        if (this.enableDebugMessages) {
                            Msg.info(this, "Adding a new edge (as uuids): " + srcUuid + " - " + dstUuid);
                            Msg.info(this, "                  (as addrs): 0x" + Long.toHexString(startAddress) + 
                                           "    0x" + Long.toHexString(destinationAddress) +
                                           "    " + reference.getReferenceType().toString());
                        }
                        CFGOuterClass.Edge.Builder newEdge = CFGOuterClass.Edge.newBuilder();
                        CFGOuterClass.EdgeLabel.Builder newEdgeLabel = CFGOuterClass.EdgeLabel.newBuilder();

                        // 
                        // Map Ghidra reference type to GTIRB edge label
                        //
                        // Mapping rules/heuristics:
                        //   - Ghidra JUMP <==> GTIRB Branch (but call stays a call)
                        //   - In Ghidra, everything is direct, unless specified as indirect
                        //   - User-added edges iin Ghidra have OVERRIDE added to the name
                        //
                        switch (reference.getReferenceType().toString()) {
                            case "CONDITIONAL_JUMP": 
                            case "CALLOTHER_OVERRIDE_JUMP": 
                                newEdgeLabel.setType(CFGOuterClass.EdgeType.Type_Branch);
                                newEdgeLabel.setConditional(true);
                                newEdgeLabel.setDirect(true);
                                break;
                            case "UNCONDITIONAL_JUMP": 
                            case "JUMP_OVERRIDE_UNCONDITIONAL": 
                                newEdgeLabel.setType(CFGOuterClass.EdgeType.Type_Branch);
                                newEdgeLabel.setConditional(false);
                                newEdgeLabel.setDirect(true);
                                break;
                            case "CONDITIONAL_CALL": 
                            case "CALLOTHER_OVERRIDE_CALL": 
                                newEdgeLabel.setType(CFGOuterClass.EdgeType.Type_Call);
                                newEdgeLabel.setConditional(true);
                                newEdgeLabel.setDirect(true);
                                break;
                            case "UNCONDITIONAL_CALL": 
                            case "CALL_OVERRIDE_UNCONDITIONAL": 
                                newEdgeLabel.setType(CFGOuterClass.EdgeType.Type_Call);
                                newEdgeLabel.setConditional(false);
                                newEdgeLabel.setDirect(true);
                                break;
                            case "CONDITIONAL_COMPUTED_JUMP": 
                                newEdgeLabel.setType(CFGOuterClass.EdgeType.Type_Branch);
                                newEdgeLabel.setConditional(true);
                                newEdgeLabel.setDirect(false);
                                break;
                            case "INDIRECTION": 
                            case "COMPUTED_JUMP": 
                                newEdgeLabel.setType(CFGOuterClass.EdgeType.Type_Branch);
                                newEdgeLabel.setConditional(false);
                                newEdgeLabel.setDirect(false);
                                break;
                            case "CONDITIONAL_COMPUTED_CALL": 
                                newEdgeLabel.setType(CFGOuterClass.EdgeType.Type_Call);
                                newEdgeLabel.setConditional(true);
                                newEdgeLabel.setDirect(false);
                                break;
                            case "COMPUTED_CALL": 
                                newEdgeLabel.setType(CFGOuterClass.EdgeType.Type_Call);
                                newEdgeLabel.setConditional(false);
                                newEdgeLabel.setDirect(false);
                                break;
                            case "FALL_THROUGH": 
                                newEdgeLabel.setType(CFGOuterClass.EdgeType.Type_Fallthrough);
                                newEdgeLabel.setConditional(false);
                                newEdgeLabel.setDirect(true);
                                break;
                            default:
                                Msg.error(this, "Export CFG: Ghidra edge type does not map to GTIRB edge type: " 
                                    + reference.getReferenceType().toString());
                                break;
                        }

                        newEdge.setLabel(newEdgeLabel)
                            .setSourceUuid(com.grammatech.gtirb.Util.uuidToByteString(srcUuid))
                            .setTargetUuid(com.grammatech.gtirb.Util.uuidToByteString(dstUuid));
                        newCFG.addEdges(newEdge);
                    }
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Export CFG: Exception iterating through blocks (second pass): " + e);
        }
        return(newCFG);
    }

    //
    // exportProgramToFile
    //
    private boolean exportProgramToFile(IR ir,
                                        OutputStream fileOut,
                                        TaskMonitor monitor) {
        //
        // Start building a new IR
        IROuterClass.IR.Builder newIR = IROuterClass.IR.newBuilder();
        IROuterClass.IR protoIR = ir.getProtoIR();

        // IR has UUID, version, and AuxData.
        newIR.setUuid(protoIR.getUuid());
        newIR.setVersion(protoIR.getVersion());

        // Add the module
        ModuleOuterClass.Module.Builder newModule =
            exportModule(ir.getModule());
        // Keep the same module name
        newModule.setName(ir.getModule().getName());
        newIR.addModules(newModule);

        // Add the CFG
        CFGOuterClass.CFG.Builder newCFG = exportCFG(ir, monitor);
        newIR.setCfg(newCFG);

        // Add the IR-level AuxData, straight from the original
        newIR.putAllAuxData(protoIR.getAuxData());

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

        // Get the program
        // (This method came from ASCII exporter)
        if (!(domainObj instanceof Program)) {
            log.appendMsg("Unsupported type: " +
                          domainObj.getClass().getName());
            return false;
        }
        this.program = (Program)domainObj;

        //
        // TODO: May want to reject an attempt to export a file that was not
        // originally GTIRB
        //       Or, if it is supported, use an alternate procedure.
        //

        // Get the IR
        // It could be that the IR loaded by the loader is still around
        // (a load followed by an export for instance). If so, use it.
        // Otherwise we need to load the file.
        IR ir = GtirbLoader.getIR();
        if (ir == null) {
            // Load the original Gtirb to preserve extra information from it.
            InputStream inputStream;
            Options programOptions = program.getOptions(Program.PROGRAM_INFO);
            byte[] gtirbBytes = programOptions.getByteArray("GtirbBytes", null);
            if (gtirbBytes == null) {
                String fileName = program.getExecutablePath();
                File inputFile = new File(fileName);
                try {
                    inputStream = new FileInputStream(inputFile);
                } catch (Exception e) {
                    Msg.error(this, "Error opening file" + e);
                    return false;
                }
                Msg.info(this, "Loading GTIRB file " + fileName);
            } else {
                inputStream = new ByteArrayInputStream(gtirbBytes);
                Msg.info(this, "Reusing imported GTIRB information");
            }
            ir = IR.loadFile(inputStream);
        }

        // Open output file
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
        return (this.exportProgramToFile(ir, fos, monitor));
    }

    //
    // getOptions
    //
    @Override
    public List<Option> getOptions(DomainObjectService domainObjectService) {
        List<Option> list = new ArrayList<>();

        // Currently no options. Comment this out, otherwise it shows up
        //  as an option dialogue when exporting
        // TODO: If this exporter has custom options, add them to 'list'
        //list.add(new Option("Option name goes here",
        //                    "Default option value goes here"));

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

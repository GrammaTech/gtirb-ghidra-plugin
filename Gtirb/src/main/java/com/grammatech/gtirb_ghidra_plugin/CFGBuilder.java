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
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/** Export handling to generate GTIRB ${@link com.grammatech.gtirb.CFG} edges
 * based on the current state of Ghidra's ${@link Program}. */
public class CFGBuilder {
    private Program program;
    private HashMap<Long, UUID> addressToBlock = null;
    private boolean enableDebugMessages = false;

    public CFGBuilder(Program program) {
        this.program = program;
        addressToBlock = new HashMap<Long, UUID>();
    }

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

    //
    // initAddressToBlockMap
    //
    // The address to block map is needed because edges are stored as UUID-UUID pairs,
    // (each UUID identifying a code block), while Ghidra considers an edge to be a pair
    // of addresses. Exporting CFG requires translating Ghidra edges to GTIRB
    // edges, and the most efficient way to get a block UUID from an address is to
    // create a map of addresses to blocks before starting the export.
    private boolean initAddressToBlockMap (ModuleOuterClass.Module.Builder protoModule) {
        // for every block, add an entry in the address to block map
        // NOTE: These are Gtirb addresses, not load addresses.
        // TODO: Sorting by address would make this a much more efficient operation.
        Module module = new Module(protoModule.build());
        module.initializeSectionList();
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

    private UUID getBlockAtAddress(ModuleOuterClass.Module.Builder module, long address, long size) {
        UUID uuid = addressToBlock.get(address);
        if (uuid == null) {
            ByteString bsUuid = ModuleBuilder.splitBlocksAtOffset(module, address, true, size);
            if (bsUuid != null) {
                uuid = Util.byteStringToUuid(bsUuid);
                addressToBlock.put(address, uuid);
            }
        }
        return uuid;
    }

    static private CFGOuterClass.EdgeLabel.Builder refTypeToLabel(RefType refType) {
        CFGOuterClass.EdgeLabel.Builder label = CFGOuterClass.EdgeLabel.newBuilder();

        //
        // Map Ghidra reference type to GTIRB edge label
        //
        // Mapping rules/heuristics:
        //   - Ghidra JUMP <==> GTIRB Branch (but call stays a call)
        //   - In Ghidra, everything is direct, unless specified as indirect
        //   - User-added edges iin Ghidra have OVERRIDE added to the name
        //
        switch (refType.toString()) {
            case "CONDITIONAL_JUMP":
            case "CALLOTHER_OVERRIDE_JUMP":
                label.setType(CFGOuterClass.EdgeType.Type_Branch);
                label.setConditional(true);
                label.setDirect(true);
                break;
            case "UNCONDITIONAL_JUMP":
            case "JUMP_OVERRIDE_UNCONDITIONAL":
                label.setType(CFGOuterClass.EdgeType.Type_Branch);
                label.setConditional(false);
                label.setDirect(true);
                break;
            case "CONDITIONAL_CALL":
            case "CALLOTHER_OVERRIDE_CALL":
                label.setType(CFGOuterClass.EdgeType.Type_Call);
                label.setConditional(true);
                label.setDirect(true);
                break;
            case "UNCONDITIONAL_CALL":
            case "CALL_OVERRIDE_UNCONDITIONAL":
                label.setType(CFGOuterClass.EdgeType.Type_Call);
                label.setConditional(false);
                label.setDirect(true);
                break;
            case "CONDITIONAL_COMPUTED_JUMP":
                label.setType(CFGOuterClass.EdgeType.Type_Branch);
                label.setConditional(true);
                label.setDirect(false);
                break;
            case "INDIRECTION":
            case "COMPUTED_JUMP":
                label.setType(CFGOuterClass.EdgeType.Type_Branch);
                label.setConditional(false);
                label.setDirect(false);
                break;
            case "CONDITIONAL_COMPUTED_CALL":
                label.setType(CFGOuterClass.EdgeType.Type_Call);
                label.setConditional(true);
                label.setDirect(false);
                break;
            case "COMPUTED_CALL":
                label.setType(CFGOuterClass.EdgeType.Type_Call);
                label.setConditional(false);
                label.setDirect(false);
                break;
            case "FALL_THROUGH":
                label.setType(CFGOuterClass.EdgeType.Type_Fallthrough);
                label.setConditional(false);
                label.setDirect(true);
                break;
            default:
                break;
        }
        return label;
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

    /**
     * Creates a GTIRB CFG object representing the edges that Ghidra knows about.
     * @param oldCFG  An existing CFG from the imported GTIRB, or null if one does not exist.
     * @param module  An exported module that contains all the blocks that edges should be generated for.
     * @return
     */
    public CFGOuterClass.CFG.Builder exportCFG(CFGOuterClass.CFG oldCFG, ModuleOuterClass.Module.Builder module)
            throws ExporterException {

        CFGOuterClass.CFG.Builder newCFG = CFGOuterClass.CFG.newBuilder();
        // Edges that existed in the original GTIRB, represented by the source and target UUIDs.
        ArrayList<Flow<UUID,UUID>> oldEdges = new ArrayList<>();
        Set<UUID> vertices = new HashSet<>();

        // Copy all edges from the original GTIRB to the new CFG. Skip if we have none.
        if (oldCFG != null) {
            List<CFGOuterClass.Edge> protoEdges = oldCFG.getEdgesList();
            for (com.grammatech.gtirb.proto.CFGOuterClass.Edge protoEdge : protoEdges) {
                CFGOuterClass.Edge.Builder newEdge = CFGOuterClass.Edge.newBuilder();
                newEdge.setLabel(protoEdge.getLabel())
                        .setSourceUuid(protoEdge.getSourceUuid())
                        .setTargetUuid(protoEdge.getTargetUuid());
                newCFG.addEdges(newEdge);

                UUID sourceUuid = com.grammatech.gtirb.Util.byteStringToUuid(protoEdge.getSourceUuid());
                UUID targetUuid = com.grammatech.gtirb.Util.byteStringToUuid(protoEdge.getTargetUuid());

                Flow<UUID, UUID> flow = new Flow<>(sourceUuid, targetUuid);
                oldEdges.add(flow);
                vertices.add(sourceUuid);
                vertices.add(targetUuid);
            }
        }

        // Initialize an address-to-block UUID look up table
        if (!initAddressToBlockMap(module)) {
            throw new ExporterException("Export CFG: Failed to initialize address-to-block look up");
        }

        long imageBase = this.program.getImageBase().getOffset();
        BasicBlockModel basicBlockModel = new BasicBlockModel(this.program, true);
        ReferenceManager referenceManager = this.program.getReferenceManager();
        try {
            CodeBlockIterator codeBlockIterator = basicBlockModel.getCodeBlocks(TaskMonitor.DUMMY);
            while (codeBlockIterator.hasNext()) {
                CodeBlock codeBlock = codeBlockIterator.next();
                long address = codeBlock.getFirstStartAddress().getOffset() - imageBase;
                long size = codeBlock.getMaxAddress().getOffset() - imageBase - address;
            }
        } catch (Exception e) {
            throw new ExporterException("Export CFG: Unable to export code blocks: " + e.getMessage());
        }

        // NOTE: Ghidra does not show returns in any case, which is different from GTIRB.
        //       That is, in GTIRB, a RET would generate an edge to a callsite, Ghidra
        //       does not do this.
        try {
            CodeBlockIterator codeBlockIterator = basicBlockModel.getCodeBlocks(TaskMonitor.DUMMY);
            while (codeBlockIterator.hasNext()) {
                CodeBlock codeBlock = codeBlockIterator.next();
                long startAddress = codeBlock.getFirstStartAddress().getOffset() - imageBase;
                long srcBlockSize = codeBlock.getMaxAddress().getOffset() - imageBase - startAddress;
                UUID srcUuid = getBlockAtAddress(module, startAddress, srcBlockSize);
                if (srcUuid == null) {
                    // This shouldn't happen normally:
                    Msg.info(this, "Export CFG: Source address does not map to a code block: 0x"
                            + Long.toHexString(startAddress));
                    continue;
                }
                // ReferenceManager.getFlowReferencesFrom() may be useful too.
                CodeBlockReferenceIterator dstIter = codeBlock.getDestinations(TaskMonitor.DUMMY);
                while (dstIter.hasNext()) {
                    CodeBlockReference dstRef = dstIter.next();
                    long dstAddr = dstRef.getDestinationAddress().getOffset() - imageBase;
                    long dstBlockSize = dstRef.getDestinationBlock().getMaxAddress().getOffset() - imageBase - dstAddr;
                    UUID dstUuid = getBlockAtAddress(module, dstAddr, dstBlockSize);
                    if (dstUuid == null)
                        continue;

                    Flow<UUID, UUID> flow = new Flow<>(srcUuid, dstUuid);
                    vertices.add(srcUuid);
                    vertices.add(dstUuid);

                    if (oldEdges.contains(flow)) {
                        // This Ghidra edge matches one that already existed in GTIRB
                        continue;
                    }

                    CFGOuterClass.Edge.Builder newEdge = CFGOuterClass.Edge.newBuilder();
                    CFGOuterClass.EdgeLabel.Builder newEdgeLabel;

                    newEdgeLabel = refTypeToLabel(dstRef.getFlowType());

                    newEdge.setLabel(newEdgeLabel)
                            .setSourceUuid(Util.uuidToByteString(srcUuid))
                            .setTargetUuid(Util.uuidToByteString(dstUuid));
                    newCFG.addEdges(newEdge);
                }
            }
        } catch (Exception e) {
            throw new ExporterException("Export CFG: Unable to populate new edges: " + e);
        }
        for (UUID vertex : vertices) {
            newCFG.addVertices(Util.uuidToByteString(vertex));
        }
        return newCFG;
    }
}

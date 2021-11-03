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
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
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
    private boolean initAddressToBlockMap (Module module) {
        // for every block, add an entry in the address to block map
        // NOTE: These are Gtirb addresses, not load addresses.
        for (Section section : module.getSections()) {
            for (ByteInterval byteInterval : section.getByteIntervals()) {
                for (ByteBlock block : byteInterval.getBlockList()) {
                    addressToBlock.put(block.getAddress(), block.getUuid());
                }
            }
        }
        return true;
    }

    private UUID getBlockAtAddress(Module module, long address, long size) {
        UUID uuid = addressToBlock.get(address);
        if (uuid == null) {
            uuid = ModuleBuilder.splitBlocksAtOffset(module, address, true, size);
            if (uuid != null) {
                addressToBlock.put(address, uuid);
            }
        }
        return uuid;
    }

    static private Edge makeEdge(UUID src, UUID dst, RefType refType) {
        boolean isConditional = false;
        boolean isDirect = false;
        Edge.EdgeType edgeType = Edge.EdgeType.Unlabelled;

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
                edgeType = Edge.EdgeType.Branch;
                isConditional = true;
                isDirect = true;
                break;
            case "UNCONDITIONAL_JUMP":
            case "JUMP_OVERRIDE_UNCONDITIONAL":
                edgeType = Edge.EdgeType.Branch;
                isConditional = false;
                isDirect = true;
                break;
            case "CONDITIONAL_CALL":
            case "CALLOTHER_OVERRIDE_CALL":
                edgeType = Edge.EdgeType.Call;
                isConditional = true;
                isDirect = true;
                break;
            case "UNCONDITIONAL_CALL":
            case "CALL_OVERRIDE_UNCONDITIONAL":
                edgeType = Edge.EdgeType.Call;
                isConditional = false;
                isDirect = true;
                break;
            case "CONDITIONAL_COMPUTED_JUMP":
                edgeType = Edge.EdgeType.Branch;
                isConditional = true;
                isDirect = false;
                break;
            case "INDIRECTION":
            case "COMPUTED_JUMP":
                edgeType = Edge.EdgeType.Branch;
                isConditional = false;
                isDirect = false;
                break;
            case "CONDITIONAL_COMPUTED_CALL":
                edgeType = Edge.EdgeType.Call;
                isConditional = true;
                isDirect = false;
                break;
            case "COMPUTED_CALL":
                edgeType = Edge.EdgeType.Call;
                isConditional = false;
                isDirect = false;
                break;
            case "FALL_THROUGH":
                edgeType = Edge.EdgeType.Fallthrough;
                isConditional = false;
                isDirect = true;
                break;
            default:
                break;
        }
        return new Edge(src, dst, edgeType, isConditional, isDirect);
    }

    /**
     * Creates a GTIRB CFG object representing the edges that Ghidra knows about.
     * @param cfg     An existing CFG from the imported GTIRB, or null if one does not exist.
     * @param module  An exported module that contains all the blocks that edges should be generated for.
     * @return
     */
    public CFG exportCFG(CFG cfg, Module module) throws ExporterException {
        // Edges that existed in the original GTIRB, represented by the source and target UUIDs.
        ArrayList<Flow<UUID,UUID>> oldEdges = new ArrayList<>();

        // All UUIDs that appear on either side of an edge
        Set<UUID> vertices = new HashSet<>();

        // Copy all edges from the original GTIRB to the new CFG. Skip if we have none.
        if (cfg != null) {
            for (Edge edge : cfg.getEdgeList()) {
                UUID sourceUuid = edge.getSourceUuid();
                UUID targetUuid = edge.getTargetUuid();

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

        // NOTE: Ghidra does not show returns in any case, which is different from GTIRB.
        //       That is, in GTIRB, a RET would generate an edge to a callsite, Ghidra
        //       does not do this.
        ArrayList<Edge> edgeList = new ArrayList<>();
        ArrayList<byte[]> vertexList = new ArrayList<>();
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

                    Edge edge = makeEdge(srcUuid, dstUuid, dstRef.getFlowType());
                    edgeList.add(edge);
                }
            }
        } catch (Exception e) {
            throw new ExporterException("Export CFG: Unable to populate new edges: " + e);
        }
        for (UUID vertex : vertices) {
            vertexList.add(Util.uuidToByteString(vertex).toByteArray());
        }
        cfg = new CFG(edgeList, vertexList);
        return cfg;
    }
}

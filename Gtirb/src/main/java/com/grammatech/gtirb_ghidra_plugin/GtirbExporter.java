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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
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
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.google.protobuf.ByteString;
import com.grammatech.gtirb.AuxData;
import com.grammatech.gtirb.IR;
import com.grammatech.gtirb.ProxyBlock;
import com.grammatech.gtirb.Section;
import com.grammatech.gtirb.Serialization;
import com.grammatech.gtirb.Symbol;
import com.grammatech.gtirb.Module;
import com.grammatech.gtirb.Block;
import com.grammatech.gtirb.proto.AuxDataOuterClass;
import com.grammatech.gtirb.proto.CFGOuterClass;
import com.grammatech.gtirb.proto.IROuterClass;
import com.grammatech.gtirb.proto.ModuleOuterClass;
import com.grammatech.gtirb.proto.ProxyBlockOuterClass;
import com.grammatech.gtirb.proto.SectionOuterClass;
import com.grammatech.gtirb.proto.SymbolOuterClass;

/**
 * TODO: Provide class-level documentation that describes what this exporter
 * does.
 */
public class GtirbExporter extends Exporter {

    /** Exporter constructor. */
    public GtirbExporter() {

        // TODO: Name the exporter and associate a file extension with it

        super("GTIRB Exporter", "gtirb", null);
    }

    private SectionOuterClass.Section.Builder exportSection(Section section) {
        SectionOuterClass.Section.Builder newSection =
            SectionOuterClass.Section.newBuilder();
        SectionOuterClass.Section protoSection = section.getProtoSection();
        newSection.mergeFrom(protoSection);
        return (newSection);
    }

    private SymbolOuterClass.Symbol.Builder exportSymbol(Symbol symbol) {
        SymbolOuterClass.Symbol.Builder newSymbol =
            SymbolOuterClass.Symbol.newBuilder();
        SymbolOuterClass.Symbol protoSymbol = symbol.getProtoSymbol();
        newSymbol.mergeFrom(protoSymbol);
        return newSymbol;
    }

    private ProxyBlockOuterClass.ProxyBlock.Builder
    exportProxyBlock(ProxyBlock proxyBlock) {
        ProxyBlockOuterClass.ProxyBlock.Builder newProxyBlock =
            ProxyBlockOuterClass.ProxyBlock.newBuilder();
        ProxyBlockOuterClass.ProxyBlock protoProxyBlock =
            proxyBlock.getProtoProxyBlock();
        newProxyBlock.mergeFrom(protoProxyBlock);
        return newProxyBlock;
    }

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
                // address Also need to UUID of the code or data block. THen I
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

        for (Section section : module.getSections()) {
            SectionOuterClass.Section.Builder newSection =
                exportSection(section);
            newModule.addSections(newSection);
        }

        for (Symbol symbol : module.getSymbols()) {
            SymbolOuterClass.Symbol.Builder newSymbol = exportSymbol(symbol);
            newModule.addSymbols(newSymbol);
        }

        for (ProxyBlock proxyBlock : module.getProxyBlockList()) {
            ProxyBlockOuterClass.ProxyBlock.Builder newProxyBlock =
                exportProxyBlock(proxyBlock);
            newModule.addProxies(newProxyBlock);
        }

        Set<String> auxDataTypes = module.getAuxData().getAuxDataTypes();
        for (String auxDataType : auxDataTypes) {
            AuxDataOuterClass.AuxData.Builder newAuxData = exportAuxData(
                module.getAuxData(), auxDataType, program, module);
            // QUESTION WHETHER CALLING build(): HERE IS CORRECT!
            AuxDataOuterClass.AuxData builtAuxData = newAuxData.build();
            newModule.putAuxData(auxDataType, builtAuxData);
        }

        return newModule;
    }

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
        newModule.setName("GTIRB of TIM");
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

        // 2. From program get file and open it
        Program program = (Program)domainObj;
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
        // THIS SHOULD BE REMEDIED WHEN THE EXPORTED IS COMPLETE
        // AT THAT POINT ALL INFO WILL BE COMING FROM THE PROGRAM
        // The proto IR is only needed here to copy from, for those
        // parts that do not yet have a exporter implemented.
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

    @Override
    public List<Option> getOptions(DomainObjectService domainObjectService) {
        List<Option> list = new ArrayList<>();

        // TODO: If this exporter has custom options, add them to 'list'
        list.add(new Option("Option name goes here",
                            "Default option value goes here"));

        return list;
    }

    @Override
    public void setOptions(List<Option> options) throws OptionException {

        // TODO: If this exporter has custom options, assign their values to the
        // exporter here
    }
}

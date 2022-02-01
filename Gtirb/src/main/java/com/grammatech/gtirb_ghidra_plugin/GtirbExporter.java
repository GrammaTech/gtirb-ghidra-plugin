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

import com.grammatech.gtirb.Module;
import com.grammatech.gtirb.*;
import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * An {@link Exporter} for exporting programs to GrammaTech Intermediate
 * Representation for Binaries (GTIRB).
 */
@SuppressWarnings("unused")
public class GtirbExporter extends Exporter {

    private Program program;
    private boolean enableDebugMessages = false;

    /** Exporter constructor. */
    public GtirbExporter() {
        // Name the exporter and associate a file extension with it
        super("GTIRB Exporter", "gtirb", null);
    }

    /**
     * Create a new GTIRB IR based on Ghidra's program data and an optional
     * input IR.
     */
    private IR exportProgramToIR(IR ir, TaskMonitor monitor) {
        ModuleBuilder moduleBuilder = new ModuleBuilder(program);
        CFGBuilder cfgBuilder = new CFGBuilder(program);

        if (ir == null) {
            ir = new IR();

            Module module;
            try {
                module = moduleBuilder.exportModule(null);
                CFG cfg = cfgBuilder.exportCFG(null, module);

                ir.setModules(Collections.singletonList(module));
                ir.setCfg(cfg);
            } catch (ExporterException e) {
                Msg.error(this, "GTIRB export failed: " + e);
                return null;
            }

        } else {
            Module module;
            try {
                module = moduleBuilder.exportModule(ir.getModules().get(0));

                CFG cfg = cfgBuilder.exportCFG(ir.getCfg(), module);

                ir.setModules(Collections.singletonList(module));
                ir.setCfg(cfg);
            } catch (ExporterException e) {
                Msg.error(this, "GTIRB export failed: " + e);
                return null;
            }
        }

        ir.setVersion(Version.gtirbProtobufVersion);

        return ir;
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

        // Get the IR
        // It could be that the IR loaded by the loader is still around
        // (a load followed by an export for instance). If so, use it.
        // Otherwise we need to load the file.
        IR ir = GtirbLoader.getIR();
        if (ir == null) {
            // Load the original Gtirb to preserve extra information from it.
            InputStream inputStream = null;
            Options programOptions = program.getOptions(Program.PROGRAM_INFO);
            String fileName = program.getExecutablePath();
            byte[] gtirbBytes = programOptions.getByteArray("GtirbBytes", null);
            if (gtirbBytes != null) {
                inputStream = new ByteArrayInputStream(gtirbBytes);
                Msg.info(this, "Reusing imported GTIRB information");
            } else if (fileName.endsWith(".gtirb")) {
                File inputFile = new File(fileName);
                try {
                    inputStream = new FileInputStream(inputFile);
                } catch (Exception e) {
                    Msg.error(this, "Error opening file" + e);
                    return false;
                }
                Msg.info(this, "Loading GTIRB file " + fileName);
            } else {
                // This program was imported with a different Ghidra Loader, not
                // originally a GTIRB.
                Msg.info(this, "Creating a new GTIRB file");
            }
            if (inputStream != null)
                ir = IR.loadFile(inputStream);
        } else {
            // Create a copy of the original Gtirb
            ir = new IR(ir.getProtoIR());
        }

        // Open output file
        FileOutputStream fos = null;
        boolean writeSuccess = false;
        ir = exportProgramToIR(ir, monitor);
        if (ir == null)
            return false;
        try {
            fos = new FileOutputStream(file);
            ir.saveFile(fos);
            writeSuccess = true;
        } catch (IOException ie) {
            Msg.error(this, "Error writing file: " + ie);
        }
        if (fos != null) {
            try {
                fos.close();
            } catch (IOException ioe) {
                Msg.error(this, "Error closing file " + ioe);
            }
        }
        return writeSuccess;
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
        // list.add(new Option("Option name goes here",
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

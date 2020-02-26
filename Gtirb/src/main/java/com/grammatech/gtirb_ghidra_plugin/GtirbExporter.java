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
import ghidra.program.model.address.AddressSetView;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** TODO: Provide class-level documentation that describes what this exporter does. */
public class GtirbExporter extends Exporter {

    /** Exporter constructor. */
    public GtirbExporter() {

        // TODO: Name the exporter and associate a file extension with it

        super("My Exporter", "exp", null);
    }

    @Override
    public boolean export(
            File file, DomainObject domainObj, AddressSetView addrSet, TaskMonitor monitor)
            throws ExporterException, IOException {

        // TODO: Perform the export, and return true if it succeeded

        return false;
    }

    @Override
    public List<Option> getOptions(DomainObjectService domainObjectService) {
        List<Option> list = new ArrayList<>();

        // TODO: If this exporter has custom options, add them to 'list'
        list.add(new Option("Option name goes here", "Default option value goes here"));

        return list;
    }

    @Override
    public void setOptions(List<Option> options) throws OptionException {

        // TODO: If this exporter has custom options, assign their values to the exporter here
    }
}

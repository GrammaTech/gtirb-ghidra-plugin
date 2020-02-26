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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** TODO: Provide class-level documentation that describes what this analyzer does. */
public class GtirbAnalyzer extends AbstractAnalyzer {

    public GtirbAnalyzer() {

        // TODO: Name the analyzer and give it a description.

        super("My Analyzer", "Analyzer description goes here", AnalyzerType.BYTE_ANALYZER);
    }

    @Override
    public boolean getDefaultEnablement(Program program) {

        // TODO: Return true if analyzer should be enabled by default

        return false;
    }

    @Override
    public boolean canAnalyze(Program program) {

        // TODO: Examine 'program' to determine of this analyzer should analyze it.  Return true
        // if it can.

        return false;
    }

    @Override
    public void registerOptions(Options options, Program program) {

        // TODO: If this analyzer has custom options, register them here

        options.registerOption(
                "Option name goes here", false, null, "Option description goes here");
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        // TODO: Perform analysis when things get added to the 'program'.  Return true if the
        // analysis succeeded.

        return false;
    }
}

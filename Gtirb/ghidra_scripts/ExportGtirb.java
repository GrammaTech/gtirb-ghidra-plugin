/*
 *  Copyright (C) 2021 GrammaTech, Inc.
 *
 *  This code is licensed under the MIT license. See the LICENSE file in the
 *  project root for license terms.
 *
 */
// This script uses the GTIRB plugin's exporter to write a GTIRB file.
//@category Update
import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import com.grammatech.gtirb_ghidra_plugin.GtirbExporter;

import java.io.File;

public class ExportGtirb extends GhidraScript {

    public void run() throws Exception {
        GtirbExporter exporter = new GtirbExporter();
        File outFile;
        try {
            outFile = new File(askString("Output", "Save"));
        } catch (CancelledException e) {
            return;
        }
        exporter.export(outFile, currentProgram, null, TaskMonitor.DUMMY);
    }
}

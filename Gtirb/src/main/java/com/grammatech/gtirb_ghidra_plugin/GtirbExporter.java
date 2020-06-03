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
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.grammatech.gtirb.AuxData;
import com.grammatech.gtirb.IR;
import com.grammatech.gtirb.ProxyBlock;
import com.grammatech.gtirb.Section;
import com.grammatech.gtirb.Symbol;
import com.grammatech.gtirb.Util;
import com.grammatech.gtirb.proto.AuxDataOuterClass;
import com.grammatech.gtirb.proto.CFGOuterClass;
import com.grammatech.gtirb.proto.IROuterClass;
import com.grammatech.gtirb.proto.ModuleOuterClass;
import com.grammatech.gtirb.proto.ProxyBlockOuterClass;
import com.grammatech.gtirb.proto.SectionOuterClass;
import com.grammatech.gtirb.proto.SymbolOuterClass;


/** TODO: Provide class-level documentation that describes what this exporter does. */
public class GtirbExporter extends Exporter {

    /** Exporter constructor. */
    public GtirbExporter() {

        // TODO: Name the exporter and associate a file extension with it

        super("GTIRB Exporter", "gtirb", null);
    }

// // // // // // // // // // // // // // // // //
    public SectionOuterClass.Section.Builder exportSection(Section section) {
    	SectionOuterClass.Section.Builder newSection = SectionOuterClass.Section.newBuilder();
    	SectionOuterClass.Section protoSection = section.getProtoSection();
    	newSection.mergeFrom(protoSection);
    	return (newSection);
    }
    
    public SymbolOuterClass.Symbol.Builder exportSymbol(Symbol symbol) {
    	SymbolOuterClass.Symbol.Builder newSymbol = SymbolOuterClass.Symbol.newBuilder();
    	SymbolOuterClass.Symbol protoSymbol = symbol.getProtoSymbol();
       	newSymbol.mergeFrom(protoSymbol);
       	return newSymbol;
    }

    public ProxyBlockOuterClass.ProxyBlock.Builder exportProxyBlock(ProxyBlock proxyBlock) {
    	ProxyBlockOuterClass.ProxyBlock.Builder newProxyBlock = ProxyBlockOuterClass.ProxyBlock.newBuilder();
    	ProxyBlockOuterClass.ProxyBlock protoProxyBlock = proxyBlock.getProtoProxyBlock();
       	newProxyBlock.mergeFrom(protoProxyBlock);
       	return newProxyBlock;
    }

    public AuxDataOuterClass.AuxData.Builder exportAuxData(AuxData auxData, String auxDataType) {
    	AuxDataOuterClass.AuxData.Builder newAuxData = AuxDataOuterClass.AuxData.newBuilder();
    	AuxDataOuterClass.AuxData protoAuxData = auxData.getProtoAuxData(auxDataType);
       	newAuxData.mergeFrom(protoAuxData);
       	return newAuxData;
    }    
    
    // Have to avoid confusion with java.io.Module
    public ModuleOuterClass.Module.Builder exportModule(com.grammatech.gtirb.Module module) {
    	ModuleOuterClass.Module.Builder newModule = ModuleOuterClass.Module.newBuilder();
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
    		SectionOuterClass.Section.Builder newSection = exportSection(section);
    		newModule.addSections(newSection);
    	}

    	for (Symbol symbol : module.getSymbols()) {
    		SymbolOuterClass.Symbol.Builder newSymbol = exportSymbol(symbol);
    		newModule.addSymbols(newSymbol);
    	}

    	for (ProxyBlock proxyBlock : module.getProxyBlockList()) {
    		ProxyBlockOuterClass.ProxyBlock.Builder newProxyBlock = exportProxyBlock(proxyBlock);
    		newModule.addProxies(newProxyBlock);
    	}

    	Set<String> auxDataTypes = module.getAuxData().getAuxDataTypes();
    	for (String auxDataType : auxDataTypes) {
    		AuxDataOuterClass.AuxData.Builder newAuxData = exportAuxData(module.getAuxData(), auxDataType);
    		AuxDataOuterClass.AuxData builtAuxData = newAuxData.build();
    		newModule.putAuxData(auxDataType, builtAuxData);
    	}   	

    	return newModule;
    }

    public boolean exportProgramToFile(Program program, IR ir, OutputStream fileOut) {
    	//
    	// Start building a new IR
    	IROuterClass.IR.Builder newIR = IROuterClass.IR.newBuilder();

    	// TODO:just as well to get IR from loader here, not needed in calling routine.
    	IROuterClass.IR protoIR = ir.getProtoIR();

    	// IR has UUID, version, and AuxData. 
    	// Ignore AuxData for now, I've never seen an example of it at the top level 
       	//newIR.mergeFrom(protoIR);
    	newIR.setUuid(protoIR.getUuid());
    	newIR.setVersion(protoIR.getVersion());
    	
    	// Add the module
    	ModuleOuterClass.Module.Builder newModule = exportModule(ir.getModule());
    	newModule.setName("GTIRB of TIM");
    	newIR.addModules(newModule);
 
    	// Add the CFG
    	CFGOuterClass.CFG.Builder newCFG = ir.getCfg().buildCFG();
    	newIR.setCfg(newCFG);
    	
    	try {
    		newIR.build().writeTo(fileOut);
    	} catch (Exception e) {
            System.out.println("Exception writing file: " + e);
            return false;
    	}
    	return true;
    }

    @Override
    public boolean export(
            File file, DomainObject domainObj, AddressSetView addrSet, TaskMonitor monitor)
            throws ExporterException, IOException {

    	// 1. Get the program
    	// (This method came from ASCII exporter)
        if (!(domainObj instanceof Program)) {
            log.appendMsg("Unsupported type: " + domainObj.getClass().getName());
            return false;
        }

        // 2. From program get file and open it
        Program program = (Program) domainObj;
        String fileName = program.getExecutablePath();
//
// TODO: May want to reject an attempt to export a file that was not originally GTIRB
//       Or, if it is supported, use an alternate procedure.
//
//        File inputFile = new File(fileName);
//        InputStream inputStream;
//        try {
//        	inputStream = new FileInputStream(inputFile);
//        }
//        catch (Exception e) {
//        	Msg.error(this, "Error opening file" + e); 
//        	return false;
//        }
        
        // 3. Load file into IR
 //       IR ir = IR.loadFile(inputStream);
        IR ir = GtirbLoader.getIR();
        
        // 4. Open output file
    	FileOutputStream fos = null;
    	boolean retval = true;
    	try {
    		fos = new FileOutputStream(file);
    	}
    	catch (IOException ie) {
        	Msg.error(this, "Error opening file" + ie);
            retval = false;
    	}
        if (retval == false) {
            if (fos != null) {
            	try {
            		fos.close();
                 }
                 catch (IOException ioe) {
                     Msg.error(this, "Error closing file " + ioe);
                 }
            }
            return false;
        }
        //return (ir.saveFile(fos));
        return (this.exportProgramToFile(program, ir, fos));
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

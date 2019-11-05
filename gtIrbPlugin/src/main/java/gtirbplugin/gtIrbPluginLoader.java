/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package gtirbplugin;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import gtIrbApi.IR;
import gtIrbApi.Module;
import gtIrbApi.Section;


/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class gtIrbPluginLoader extends AbstractLibrarySupportLoader {
	
	private FileBytes fileBytes;
	private Listing listing;
	private Memory memory;

	private void setImageBase(Program program) {
		try {
			AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
			// If I knew of a different image base, I would set it here instead of using "0"
			Address imageBase = defaultSpace.getAddress(0, true);
			program.setImageBase(imageBase, true);
		}
		catch (Exception e) {
			// this shouldn't happen
			Msg.error(this, "Can't set image base.", e);
		}
	}

	@Override
	public String getName() {

		// TODO: Name the loader.  This name must match the name of the loader in the .opinion 
		// files.

		return "GTIRB loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// TODO: Examine the bytes in 'provider' to determine if this loader can load it.  If it 
		// can load it, return the appropriate load specifications.

		String path = provider.getAbsolutePath();
		if (path.endsWith(gtIrbPluginConstants.GTIRB_EXTENSION)) {
			LanguageCompilerSpecPair lcs = new LanguageCompilerSpecPair("x86:LE:64:default", "gcc");
			loadSpecs.add(new LoadSpec(this, 0, lcs, true));
		}
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		setImageBase(program);
		InputStream fileIn = provider.getInputStream(0);
		IR ir = new IR();
        //long byteOffset = 0;
        Address loadAddress;

        if (ir.loadFile(fileIn) != true) {
        	Msg.error(this, "Unable to load GTIRB file");
        	return;
        }
        
        // Handling one module, for the moment.
        // Have to be specific about this type because java.lang has a "Module"
        Module module = ir.getModule();
        ArrayList<Section> sections = module.getSections();
        String blockComment = "Block Comment";
        String blockSource = "GTIRB Loader";
        for (Section s: sections) {
        	Msg.debug(this, "Section name: " + s.getName());
        	Msg.debug(this, "Section address: " + s.getAddress());
        	Msg.debug(this, "Section size: " + s.getSize());
        	
        	/*
        	 * public static MemoryBlock createInitializedBlock(
        	 * 			Program program, boolean isOverlay, String name, Address start, 
        	 * 			InputStream dataInput, long length, String comment, String source, 
        	 * 			boolean r, boolean w, boolean x, MessageLog log, Monitor monitor)
        	 */
        	byte[] byteArray = module.getBytes(s.getAddress(), (int)s.getSize());
        	if (byteArray == null) {
        		Msg.debug(this, "Skipping " + s.getName() + ", no bytes in ImageByteMap.");
        		continue;
        	}
            loadAddress = program.getImageBase().add(s.getAddress());
            InputStream dataInput = new ByteArrayInputStream(byteArray);
        	try {
        		MemoryBlockUtils.createInitializedBlock(program, false, s.getName(),
            		loadAddress, dataInput, s.getSize(), blockComment, 
            		blockSource, true, false, false, log, monitor);
        	}
            catch (AddressOverflowException e) {
            	Msg.debug(this, "!!!! Address Overflow Exception !!!!");
            	continue;
            }
        }
        
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}

	public FileBytes getFileBytes() {
		return fileBytes;
	}

	public void setFileBytes(FileBytes fileBytes) {
		this.fileBytes = fileBytes;
	}

	public Listing getListing() {
		return listing;
	}

	public void setListing(Listing listing) {
		this.listing = listing;
	}

	public Memory getMemory() {
		return memory;
	}

	public void setMemory(Memory memory) {
		this.memory = memory;
	}
}

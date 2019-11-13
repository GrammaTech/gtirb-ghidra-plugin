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
package gtirb;

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
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import gtirbApi.Block;
import gtirbApi.DataObject;
import gtirbApi.IR;
import gtirbApi.Kind;
import gtirbApi.Module;
import gtirbApi.Node;
import gtirbApi.Section;
import gtirbApi.Symbol;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

/** TODO: Provide class-level documentation that describes what this loader does. */
public class gtirbLoader extends AbstractLibrarySupportLoader {

    public static final String GTIRB_NAME = "GrammaTech's IR for Binaries (GTIRB)";

    private FileBytes fileBytes;
    private Listing listing;
    private Memory memory;

    private void setImageBase(Program program) {
        try {
            AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
            // If I knew of a different image base, I would set it here instead of using "0"
            Address imageBase = defaultSpace.getAddress(0, true);
            program.setImageBase(imageBase, true);
        } catch (Exception e) {
            // this shouldn't happen
            Msg.error(this, "Can't set image base.", e);
        }
    }

    public boolean addSymbol(Symbol symbol, Address address, Program program) {
        Namespace namespace = null;
        String name = symbol.getName();
        SymbolTable symbolTable = program.getSymbolTable();
        try {
            symbolTable.createLabel(address, name, namespace, SourceType.IMPORTED);
        } catch (InvalidInputException e) {
            Msg.error(this, "createLabel threw Invalid Input Exception");
        }
        return true;
    }
    //		TaskMonitor monitor) {
    //
    //		Data array = null;
    //		try {
    //			array = listing.createData(symbolTableAddr, symbolTable.toDataType());
    //		}
    //		catch (Exception e) {
    //			log("Failed to properly markup symbol table at " + symbolTableAddr + ": " +
    //				getMessage(e));
    //			return;
    //		}
    //
    //		ElfSymbol[] symbols = symbolTable.getSymbols();
    //		for (int i = 0; i < symbols.length; ++i) {
    //			int stringOffset = symbols[i].getName();
    //			if (stringOffset == 0) {
    //				continue;
    //			}
    //			Data structData = array.getComponent(i);
    //			if (structData != null) {
    //				structData.setComment(CodeUnit.EOL_COMMENT, symbols[i].getNameAsString());
    //			}
    //		}
    //	}

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
        if (path.endsWith(gtirbConstants.GTIRB_EXTENSION)) {
            LanguageCompilerSpecPair lcs = new LanguageCompilerSpecPair("x86:LE:64:default", "gcc");
            loadSpecs.add(new LoadSpec(this, 0, lcs, true));
        }
        return loadSpecs;
    }

    @Override
    protected void load(
            ByteProvider provider,
            LoadSpec loadSpec,
            List<Option> options,
            Program program,
            TaskMonitor monitor,
            MessageLog log)
            throws CancelledException, IOException {

        monitor.setMessage("Completing GTIRB parsing...");
        setImageBase(program);
        program.setExecutableFormat(gtirbLoader.GTIRB_NAME);

        InputStream fileIn = provider.getInputStream(0);
        IR ir = new IR();
        // long byteOffset = 0;
        Address loadAddress;

        if (ir.loadFile(fileIn) != true) {
            Msg.error(this, "Unable to load GTIRB file");
            return;
        }

        // Handling one module, for the moment.
        Module module = ir.getModule();

        //
        // There is a sequencing problem with file format and ISA identification. Ghidra expects to
        // know these things
        // before choosing which loader to use to load the file, set the the language specification.
        // I have to do one of these things:
        // - Find a way to change language specification if the module does not match what got me
        // here, or
        // - Put an additional parsing of the file earlier on in the process, or
        // - Just exit. that is, only support IA64/LE/ELF.
        if (module.getFileFormat() == Module.GTIRB_FILE_FORMAT_ELF) {
            Msg.debug(this, "File type is ELF.");
        } else {
            Msg.debug(
                    this,
                    "File Format is not ELF (ID = "
                            + module.getFileFormat()
                            + "), so far only ELF is supported");
        }
        if (module.getISA() == Module.GTIRB_ISA_X64) {
            Msg.debug(this, "ISA is X64.");
        } else {
            Msg.debug(
                    this,
                    "ISA is not X64 (ID = " + module.getISA() + "), so far only X86 is supported");
        }

        monitor.setMessage("Processing program sections...");
        ArrayList<Section> sections = module.getSections();
        String blockComment = "Block Comment";
        String blockSource = "GTIRB Loader";
        for (Section s : sections) {
            // Msg.debug(this, "Section name: " + s.getName());
            // Msg.debug(this, "Section address: " + s.getAddress());
            // Msg.debug(this, "Section size: " + s.getSize());

            /*
             * public static MemoryBlock createInitializedBlock(
             * 			Program program, boolean isOverlay, String name, Address start,
             * 			InputStream dataInput, long length, String comment, String source,
             * 			boolean r, boolean w, boolean x, MessageLog log, Monitor monitor)
             */
            byte[] byteArray = module.getBytes(s.getAddress(), (int) s.getSize());
            if (byteArray == null) {
                // Msg.debug(this, "Skipping " + s.getName() + ", no bytes in ImageByteMap.");
                continue;
            }
            loadAddress = program.getImageBase().add(s.getAddress());
            InputStream dataInput = new ByteArrayInputStream(byteArray);
            // Actually some of these _should_ be overlay
            try {
                MemoryBlockUtils.createInitializedBlock(
                        program,
                        false,
                        s.getName(),
                        loadAddress,
                        dataInput,
                        s.getSize(),
                        blockComment,
                        blockSource,
                        true,
                        false,
                        false,
                        log,
                        monitor);
            } catch (AddressOverflowException e) {
                Msg.error(this, "!!!! Address Overflow Exception !!!!");
                continue;
            }
        }

        //// Debug only: print out the image byte map
        // ImageByteMap imageByteMap = module.getImageByteMap();
        // void printImageByteMap() {
        //    for (Region range : imageByteMap.regionList) {
        //        long startAddr = range.getStartAddress();
        //        int length = range.getLength();
        //        long endAddr = startAddr + length - 1;
        //        Msg.debug(
        //                this,
        //                "From "
        //                        + String.format("0x%08X", startAddr)
        //                        + " To "
        //                        + String.format("0x%08X", endAddr)
        //                        + "     size: "
        //                        + String.format("%d", length)
        //                        + " ("
        //                        + String.format("0x%x)", length));
        //    }
        // }

        // A symbol is a label which also has an address, a symbol type and a source type.
        // This code adds all symbols as type CODE and source IMPORTED. Also the addresses
        // come from the gtirb referent UUID. See the gtirb data symbols example code.
        //
        // I do not know if this is correct.
        //
        // The other option to look at is like that of ELF (see markupSymbolTable in
        // elfProgramBuilder)
        // in which the symbol table is loaded at a certain address, the block is cast as "Data" and
        // iterated through,
        // and the symbol address is the address in that table, references should then be created
        // for each data
        // or code referent.
        // OR, maybe I should actually be looking at the .symtab section? At least there all the
        // symbols
        // have an address. (Buut what if not ELF or otherwise no .symtab?)
        ArrayList<Symbol> symbols = module.getSymbols();
        for (Symbol symbol : symbols) {
            // Msg.debug(this, "Symbol " + symbol.getName());
            UUID referentUuid = symbol.getReferentUuid();
            if (referentUuid.equals(gtirbApi.Util.nilUuid)) {
                // Msg.debug(this, "  - has no referent.");
                continue;
            }
            Node referent = symbol.getByUuid(referentUuid);
            if (referent == null) {
                // Msg.debug(this, "  - has an unregistered referent.");
                continue;
            } else if (referent.getKind() == Kind.DataObject) {
                DataObject dataObject = (DataObject) referent;
                // Msg.debug(this, "  - Data Object Address " + dataObject.getAddress());
                Address symbolAddress = program.getImageBase().add(dataObject.getAddress());
                addSymbol(symbol, symbolAddress, program);
            } else if (referent.getKind() == Kind.Block) {
                Block block = (Block) referent;
                // Msg.debug(this, "  - Block Address " + block.getAddress());
                Address symbolAddress = program.getImageBase().add(block.getAddress());
                addSymbol(symbol, symbolAddress, program);
            } else if (referent.getKind() == Kind.ProxyBlock) {
                // Msg.debug(this, "  - Proxy Block");
                ;
            }
            // else {
            //	//Msg.debug(this, "  - Unrecognized referent.");
            // }
        }
    }

    @Override
    public List<Option> getDefaultOptions(
            ByteProvider provider,
            LoadSpec loadSpec,
            DomainObject domainObject,
            boolean isLoadIntoProgram) {
        List<Option> list =
                super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

        // TODO: If this loader has custom options, add them to 'list'
        list.add(new Option("Option name goes here", "Default option value goes here"));

        return list;
    }

    @Override
    public String validateOptions(
            ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

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

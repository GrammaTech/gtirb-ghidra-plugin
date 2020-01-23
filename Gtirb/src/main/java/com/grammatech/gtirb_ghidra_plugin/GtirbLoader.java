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
package com.grammatech.gtirb_ghidra_plugin;

import com.grammatech.gtirb.Block;
import com.grammatech.gtirb.ByteInterval;
import com.grammatech.gtirb.CodeBlock;
import com.grammatech.gtirb.DataBlock;
import com.grammatech.gtirb.IR;
import com.grammatech.gtirb.Module;
import com.grammatech.gtirb.Node;
import com.grammatech.gtirb.Section;
import com.grammatech.gtirb.Symbol;
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
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

/** TODO: Provide class-level documentation that describes what this loader does. */
public class GtirbLoader extends AbstractLibrarySupportLoader {

    public static final String GTIRB_NAME = "GrammaTech's IR for Binaries (GTIRB)";

    private IR ir; // NOT SURE I REALLY NEED TO SAVE THIS HERE
    private FileBytes fileBytes;
    private Listing listing;
    private Memory memory;
    private HashMap<String, GtirbFunction> functionMap;
    private HashMap<String, Namespace> namespaceMap;
    private HashMap<UUID, Long> byteIntervalLoadAddresses;

    private String getFunctionName(Module m, UUID feBlockUuid) {
        ArrayList<Symbol> symbols = m.getSymbols();
        UUID referentUuid;
        //
        // Iterate through symbols looking for the one whose referent is the
        // function entry block.
        //
        for (Symbol symbol : symbols) {
            referentUuid = symbol.getReferentByUuid();
            if (!referentUuid.equals(com.grammatech.gtirb.Util.NIL_UUID)) {
                Node referent = symbol.getByUuid(referentUuid);
                if (referent == null) {
                    continue;
                }
                if (referentUuid.equals(feBlockUuid)) {
                    Msg.debug(this, "Found referrent UUID for " + symbol.getName());
                    if (referent instanceof CodeBlock) {
                        Msg.debug(this, "Found function named " + symbol.getName());
                    } else {
                        Msg.debug(this, "But does not match CodeBlock type with instance of!");
                    }
                    return symbol.getName();
                }
            }
        }
        return ("");
    }

    // Depends on gtirbApi Symbols and AuxData, so those must be loaded before calling this.
    private boolean initializeFunctionMap(Module m) {
        this.functionMap = new HashMap<String, GtirbFunction>();
        String functionName;
        Map<UUID, ArrayList<UUID>> functionEntries = m.getAuxData().getFunctionEntries();
        Map<UUID, ArrayList<UUID>> functionBlocks = m.getAuxData().getFunctionBlocks();

        //
        // Process the Function Entries AuxData, which is a list of UUIDs of code blocks
        // that are entries to a function.
        for (Map.Entry<UUID, ArrayList<UUID>> entry : functionEntries.entrySet()) {
            UUID feUuid = entry.getKey();
            List<UUID> feBlockList = entry.getValue();

            // Presumably there is a first element in the list of function entries
            // TODO: Assuming it is a block! Should check!
            // Find the function name by searching for the symbol that refers to this UUID
            UUID feFirstBlockUuid = feBlockList.get(0);
            functionName = getFunctionName(m, feFirstBlockUuid);
            if (functionName.length() <= 0) {
                continue;
            }
            if (functionMap.containsKey(functionName)) {
                // This is a duplicate function name!
                // TODO need to resolve this correctly.
                // For now just throw an error and go on
                Msg.error(this, "Duplicate function: " + functionName);
                continue;
            }
            // Get the code block of this function entry
            Node node = new Node();
            CodeBlock functionEntryBlock = (CodeBlock) node.getByUuid(feFirstBlockUuid);
            // if (functionEntryBlock.getKind() != Kind.CodeBlock) {
            if (!(functionEntryBlock instanceof CodeBlock)) {
                Msg.error(this, "Function entry block is not code block (using instanceof)??!!");
            }
            // Go through function block aux data, adding up the sizes to get the size of the
            // function
            // TODO: This makes assumption of being contiguous!
            int functionSize = 0;
            CodeBlock functionBlock;
            List<UUID> blockList = functionBlocks.get(feUuid);
            for (UUID blockUuid : blockList) {
                functionBlock = (CodeBlock) node.getByUuid(blockUuid);
                functionSize += functionBlock.getSize();
            }
            UUID byteIntervalUuid = functionEntryBlock.getByteIntervalUuid();
            long byteIntervalLoadAddress = 0;
            Msg.debug(
                    this,
                    "Function "
                            + functionName
                            + " looking for load address of byte interval "
                            + byteIntervalUuid);
            if (byteIntervalLoadAddresses.containsKey(byteIntervalUuid)) {
                byteIntervalLoadAddress = byteIntervalLoadAddresses.get(byteIntervalUuid);
            } else {
                Msg.error(this, "Unable to get load address for byte interval!!??");
            }

            // Compute load address of function (i.e. offset from image base address)
            long functionAddress = functionEntryBlock.getOffset() + byteIntervalLoadAddress;

            // Create a function object (Is this really necessary?)
            GtirbFunction function =
                    new GtirbFunction(functionName, functionAddress, functionSize, feUuid);
            functionMap.put(functionName, function);
        }
        return true;
    }

    private GtirbFunction getFunctionContainingAddress(long address) {
        for (Map.Entry<String, GtirbFunction> entry : functionMap.entrySet()) {
            GtirbFunction function = entry.getValue();
            long start = function.getAddress();
            long end =
                    start
                            + function.getSize()
                            + 8; // Add one because address ranges are inclusive (add sizeof(long))
            if ((address >= start) && (address <= end)) {
                return function;
            }
        }
        return null;
    }

    private void setImageBase(Program program) {
        //
        // TODO: Work with load address:
        // GTIRB modules have preferred load address and rebase delta but always are 0.
        // ELF loader has a configuration option with default value of 0x10000
        // This involves creating a new class like "ElfLoaderOptionsFactory".
        // I should use GTIRB load address, and if that is 0 use a load option like ELF.
        // Until I do that I am hardcoding a load address of 0x100000.
        long defaultLoadAddress = 0x100000;
        try {
            AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
            // If I knew of a different image base, I would set it here instead of using "0"
            // Address imageBase = defaultSpace.getAddress(0, true);
            Address imageBase = defaultSpace.getAddress(defaultLoadAddress, true);
            program.setImageBase(imageBase, true);
        } catch (Exception e) {
            // this shouldn't happen
            Msg.error(this, "Can't set image base.", e);
        }
    }

    public void markAsCode(Program program, long start, long length) {
        // TODO: this should be in a common place, so all importers can communicate that something
        // is code or data.
        AddressSetPropertyMap codeProp = program.getAddressSetPropertyMap("CodeMap");
        if (codeProp == null) {
            try {
                codeProp = program.createAddressSetPropertyMap("CodeMap");
            } catch (DuplicateNameException e) {
                codeProp = program.getAddressSetPropertyMap("CodeMap");
            }
        }

        Address startAddress = program.getImageBase().add(start);
        Address endAddress = startAddress.add(length + 1);

        if (codeProp != null) {
            codeProp.add(startAddress, endAddress);
        }
    }

    public boolean addFunction(GtirbFunction function, Program program) {
        long start = function.getAddress();
        long end = start + function.getSize();
        Address imageBase = program.getImageBase();
        Address entryAddress = imageBase.add(start);
        Address lastAddress = imageBase.add(end - 1);
        AddressSet body = new AddressSet(entryAddress, lastAddress);
        try {
            this.listing.createFunction(
                    function.getName(), entryAddress, body, SourceType.IMPORTED);
        } catch (Exception e) {
            Msg.error(this, "Unable to add function: " + function.getName());
            return false;
        }
        Msg.debug(
                this,
                "Added " + function.getName() + " at " + String.format("%08X", (start + 0x100000)));
        return true;
    }

    public boolean addSymbol(Symbol symbol, Address address, Program program, Namespace namespace) {
        String name = symbol.getName();
        SymbolTable symbolTable = program.getSymbolTable();
        try {
            symbolTable.createLabel(address, name, namespace, SourceType.IMPORTED);
        } catch (InvalidInputException e) {
            Msg.error(this, "addSymbol threw Invalid Input Exception");
            return false;
        }
        return true;
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
        if (path.endsWith(GtirbConstants.GTIRB_EXTENSION)) {
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

        monitor.setMessage("Loading GTIRB ...");
        setImageBase(program);
        program.setExecutableFormat(GtirbLoader.GTIRB_NAME);
        this.listing = program.getListing();

        //
        // Load the GTIRB file into the IR
        //
        InputStream fileIn = provider.getInputStream(0);
        this.ir = IR.loadFile(fileIn);
        if (this.ir == null) {
            Msg.error(this, "Unable to load GTIRB file");
            return;
        }

        //
        // TODO: The operations that follow should be done per module.
        // For the moment only the first module is getting loaded.
        Module module = this.ir.getModule();

        //
        // Examine the modules ISA and File Format
        //
        // TODO: There is a sequencing problem with file format and ISA identification.
        // Language specification (ISA/Endian/FileFormat) is chosen before choosing which loader to
        // use.
        // The process for selecting language spec involves .opinion files and I haven't figured it
        // out yet.
        // Currently I am letting Ghidra autoselect the language spec, then forcing the choice of
        // loader
        // based on the file extension of ".gtirb". See this.findSupportedLoadSpecs().
        //
        // I may be able to resolve this by add/modifying opinion files. If not, I have to do one of
        // these things:
        // - Find a way to change language specification if the module does not match what got me
        // here, or
        // - Put an additional parsing of the file earlier on in the process, or
        // - Just exit. that is, only support IA64/LE/ELF.
        //
        if (module.getFileFormat() == Module.FileFormat.ELF) {
            Msg.debug(this, "File type is ELF.");
        } else {
            Msg.debug(
                    this,
                    "File Format is not ELF (ID = "
                            + module.getFileFormat()
                            + "), so far only ELF is supported");
        }
        if (module.getISA() == Module.ISA.X64) {
            Msg.debug(this, "ISA is X64.");
        } else {
            Msg.debug(
                    this,
                    "ISA is not X64 (ID = " + module.getISA() + "), so far only X86 is supported");
        }

        //
        // Create Namespaces and add them to a list for later use.
        //
        namespaceMap = new HashMap<String, Namespace>();
        SymbolTable symbolTable = program.getSymbolTable();
        Namespace storageUndefined;
        Namespace storageNormal;
        Namespace storageStatic;
        Namespace storageExtern;
        try {
            storageUndefined =
                    symbolTable.createNameSpace(null, "Storage_Undefined", SourceType.IMPORTED);
            // TODO: This namespace is actually not needed:
            // Normal means global, should use null instead
            storageNormal =
                    symbolTable.createNameSpace(null, "Storage_Normal", SourceType.IMPORTED);
            // Static means in the module namespace.
            if (module.getName().isEmpty()) {
                storageStatic =
                        symbolTable.createNameSpace(null, "MODULE_NAME", SourceType.IMPORTED);
            } else {
                storageStatic =
                        symbolTable.createNameSpace(null, module.getName(), SourceType.IMPORTED);
            }
            storageExtern = symbolTable.createNameSpace(null, "EXTERNAL", SourceType.IMPORTED);
        } catch (Exception e) {
            Msg.error(this, "load threw Exception on createNamespace");
            return;
        }
        namespaceMap.put("Storage_Undefined", storageUndefined);
        namespaceMap.put("Storage_Normal", storageNormal);
        namespaceMap.put("Storage_Static", storageStatic);
        namespaceMap.put("Storage_Extern", storageExtern);

        //
        // Process section information
        // Iterate through the IR section tables, loading each section into program memory
        // TODO: Some sections should be loaded as overlays, this is ignored at the moment
        //       All GTIRB sections have an address, I'm not sure implementing overlays
        //       as in ELF is really called for. Just load the sections as they are.
        // TODO: Block comment and source should be a little more useful.
        //
        monitor.setMessage("Processing program sections...");
        ArrayList<Section> sections = module.getSections();
        String blockSource = "GTIRB Loader";
        Address loadAddress;
        long offset = 0;
        Long loadedAddress;
        this.byteIntervalLoadAddresses = new HashMap<UUID, Long>();
        for (Section s : sections) {
            int sectionSize = 0;
            long sectionOffset = offset + 0x100000;

            // Go through the byte intervals of this section
            List<ByteInterval> byteIntervals = s.getByteIntervals();
            for (ByteInterval b : byteIntervals) {
                // If byte interval does not have an address, can't be loaded
                // TODO: Investigate creating sequence of fake addresses for these?
                if (b.hasAddress()) {
                    Msg.error(
                            this,
                            "Unable to load section "
                                    + s.getName()
                                    + "byte interval already has address "
                                    + b.getAddress());
                } else {
                    loadAddress = program.getImageBase().add(offset);
                    byte[] byteArray = com.grammatech.gtirb.Util.toByteArray(b.getBytes());
                    if (byteArray == null) {
                        continue;
                    }
                    InputStream dataInput = new ByteArrayInputStream(byteArray);
                    String blockComment = "";
                    try {
                        MemoryBlockUtils.createInitializedBlock(
                                program,
                                false,
                                s.getName(),
                                loadAddress,
                                dataInput,
                                b.getSize(),
                                blockComment,
                                blockSource,
                                true,
                                false,
                                false,
                                log,
                                monitor);
                    } catch (AddressOverflowException e) {
                        Msg.error(this, "Address Overflow Exception.");
                        return;
                    }
                    loadedAddress = Long.valueOf(offset);
                    Msg.error(
                            this,
                            "Putting section "
                                    + s.getName()
                                    + " byte interval "
                                    + b.getUuid()
                                    + " into hashmap");
                    byteIntervalLoadAddresses.put(b.getUuid(), loadedAddress);
                    offset += b.getSize();
                    sectionSize += b.getSize();
                }
            }

            // Report on this section and increment the offset for the next section
            Msg.debug(
                    this,
                    "Section: "
                            + s.getName()
                            + ", "
                            + String.format("%08X", sectionOffset)
                            + " - "
                            + String.format("%08X", sectionOffset + sectionSize));
            // Force byte interval alignments to 16
            // offset += sectionSize;
            offset = (offset & 0xfffffff0) + 0x10;
        }

        //
        // Get function information from AuxData
        // Iterate through the function blocks and function entry auxdata, adding the functions
        // found this way to a local map based on function name. The map is used below for
        // providin gfunction information to Ghidra and resolving local symbols.
        //
        monitor.setMessage("Initializing function map...");
        initializeFunctionMap(module);
        // for (Map.Entry mapElement : functionMap.entrySet()) {
        // here is where you should work out the functions
        // }

        //
        // Process symbol information
        // Iterate through the symbol table in gtirb IR, adding symbol information to Ghidra.
        //
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
        // have an address. (But what if not ELF or otherwise no .symtab?)
        monitor.setMessage("Initializing symbol table...");
        ArrayList<Symbol> symbols = module.getSymbols();
        for (Symbol symbol : symbols) {

            // If this is a function, add it to the program
            if (functionMap.containsKey(symbol.getName())) {
                GtirbFunction function = functionMap.get(symbol.getName());
                addFunction(function, program);
                continue;
            }

            // The rest of these need a referent to get an address
            UUID referentUuid = symbol.getReferentByUuid();
            if (referentUuid.equals(com.grammatech.gtirb.Util.NIL_UUID)) {
                continue;
            }
            Node referent = symbol.getByUuid(referentUuid);
            if (referent == null) {
                continue;
                // } else if (referent.getKind() == Kind.CodeBlock) {
            } else if (referent instanceof CodeBlock) {
                CodeBlock codeBlock = (CodeBlock) referent;
                Address symbolAddress = program.getImageBase().add(codeBlock.getOffset());
                addSymbol(symbol, symbolAddress, program, null);
                // TODO: Here is where you can add mark the block is code
                // } else if (referent.getKind() == Kind.DataBlock) {
            } else if (referent instanceof DataBlock) {
                DataBlock dataBlock = (DataBlock) referent;
                Address symbolAddress = program.getImageBase().add(dataBlock.getOffset());
                addSymbol(symbol, symbolAddress, program, null);
                // } else if (referent.getKind() == Kind.ProxyBlock) {
                // Not yet sure what to do if anything
            }
        }

        //
        // Process the code blocks
        // Iterate through the Block table in gtirb IR.
        // The blocks have already been loaded into program memory, this operation just marks
        // them as code as opposed to data or other.
        //
        // ArrayList<Block> blockList = module.getBlockList();
        // for (Block block : blockList) {
        //    markAsCode(program, block.getAddress(), block.getSize());
        // }
        for (Section s : sections) {
            List<ByteInterval> byteIntervals = s.getByteIntervals();
            for (ByteInterval b : byteIntervals) {
                if (b.hasAddress()) {
                    List<Block> blockList = b.getBlockList();
                    for (Block block : blockList) {
                        CodeBlock codeBlock = block.getCodeBlock();
                        if (codeBlock != null)
                            markAsCode(program, codeBlock.getOffset(), codeBlock.getSize());
                    }
                }
            }
        }

        //
        // Further TODOs:
        // Process CFG
        // Process DataObject Table
        // Process SmbolicExpression table

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

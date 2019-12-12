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

    private IR ir; // NOT SURE I REALLY NEED TO SAVE THIS HERE
    private FileBytes fileBytes;
    private Listing listing;
    private Memory memory;
    private HashMap<String, gtirbFunction> functionMap;
    private HashMap<String, Namespace> namespaceMap;

    private String getFunctionName(Module m, UUID feBlockUuid) {
        ArrayList<Symbol> symbols = m.getSymbols();
        UUID referentUuid;
        //
        // Iterate through symbols looking for the one whose referent is the
        // function entry block.
        //
        for (Symbol symbol : symbols) {
            referentUuid = symbol.getReferentUuid();
            if (!referentUuid.equals(gtirbApi.Util.nilUuid)) {
                Node referent = symbol.getByUuid(referentUuid);
                if (referent == null) {
                    continue;
                }

                if (referentUuid.equals(feBlockUuid) && referent.getKind() == Kind.Block) {
                    return symbol.getName();
                }
            }
        }
        return ("");
    }

    // Depends on gtirbApi Symbols and AuxData, so those must be loaded before calling this.
    private boolean initializeFunctionMap(Module m) {
        this.functionMap = new HashMap<String, gtirbFunction>();
        String functionName;
        Map<UUID, ArrayList<UUID>> functionEntries = m.getAuxData().getFunctionEntries();
        Map<UUID, ArrayList<UUID>> functionBlocks = m.getAuxData().getFunctionBlocks();

        for (Map.Entry<UUID, ArrayList<UUID>> entry : functionEntries.entrySet()) {
            UUID feUuid = entry.getKey();
            List<UUID> feBlockList = entry.getValue();

            // Presumably there is a first element in the list of function entries
            // TODO: Assuming it is a block! Should check!
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
            Node node = new Node();
            Block functionEntryBlock = (Block) node.getByUuid(feFirstBlockUuid);
            long functionAddress = functionEntryBlock.getAddress();

            int functionSize = 0;
            Block functionBlock;
            List<UUID> blockList = functionBlocks.get(feUuid);
            for (UUID blockUuid : blockList) {
                functionBlock = (Block) node.getByUuid(blockUuid);
                functionSize += functionBlock.getSize();
            }
            gtirbFunction function =
                    new gtirbFunction(functionName, functionAddress, functionSize, feUuid);
            functionMap.put(functionName, function);
        }
        return true;
    }

    private gtirbFunction getFunctionContainingAddress(long address) {
        for (Map.Entry<String, gtirbFunction> entry : functionMap.entrySet()) {
            String functionName = entry.getKey();
            gtirbFunction function = entry.getValue();
            long start = function.getAddress();
            long end = start + function.getSize();
            if ((address >= start) && (address < end)) {
                return function;
            }
        }
        return null;
    }

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

    public boolean addFunction(gtirbFunction function, Program program) {
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
        return true;
    }

    public boolean addSymbol(Symbol symbol, Address address, Program program, Namespace namespace) {
        // Namespace namespace;
        // if (symbol.getStorageKind() == Symbol.GTIRB_STORAGE_LOCAL) {
        //	namespace = this.storageLocal;
        // }
        // else if (symbol.getStorageKind() == Symbol.GTIRB_STORAGE_EXTERN) {
        //	namespace = this.storageExtern;
        // }
        // else if (symbol.getStorageKind() == Symbol.GTIRB_STORAGE_STATIC) {
        //	namespace = this.storageStatic;
        // }
        // else if (symbol.getStorageKind() == Symbol.GTIRB_STORAGE_NORMAL) {
        //	namespace = null;
        // }
        // else
        //	namespace = this.storageUndefined;
        // Namespace namespace = this.namespaceMap.get("Storage_Normal");
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

        monitor.setMessage("Loading GTIRB ...");
        setImageBase(program);
        program.setExecutableFormat(gtirbLoader.GTIRB_NAME);
        this.listing = program.getListing();

        //
        // Load the GTIRB file into the IR
        //
        InputStream fileIn = provider.getInputStream(0);
        this.ir = new IR();

        if (this.ir.loadFile(fileIn) != true) {
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
        // TODO: Some sections should be loaded as overlays, this is ignoered at the moment
        // TODO: Block comment and source should be a little more useful.
        //
        monitor.setMessage("Processing program sections...");
        ArrayList<Section> sections = module.getSections();
        String blockComment = "Block Comment";
        String blockSource = "GTIRB Loader";
        Address loadAddress;
        for (Section s : sections) {

            byte[] byteArray = module.getBytes(s.getAddress(), (int) s.getSize());
            if (byteArray == null) {
                continue;
            }
            loadAddress = program.getImageBase().add(s.getAddress());
            InputStream dataInput = new ByteArrayInputStream(byteArray);

            //
            // TODO: Actually some of these _should_ be overlay
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

        //
        // Get function information from AuxData
        // Iterate through the function blocks and function entry auxdata, adding the functions
        // found this way to a local map based on function name. The map is used below for
        // providin gfunction information to Ghidra and resolving local symbols.
        //
        monitor.setMessage("Initializing function map...");
        initializeFunctionMap(module);

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
        // have an address. (Buut what if not ELF or otherwise no .symtab?)
        monitor.setMessage("Initializing symbol table...");
        ArrayList<Symbol> symbols = module.getSymbols();
        for (Symbol symbol : symbols) {

            // If this is a function, add it to the program
            if (functionMap.containsKey(symbol.getName())) {
                gtirbFunction function = functionMap.get(symbol.getName());
                addFunction(function, program);
                continue;
            }

            // The rest of these need a referent to get an address
            UUID referentUuid = symbol.getReferentUuid();
            if (referentUuid.equals(gtirbApi.Util.nilUuid)) {
                continue;
            }
            Node referent = symbol.getByUuid(referentUuid);
            if (referent == null) {
                // Msg.debug(this, "  - has an unregistered referent.");
                continue;
            } else if (referent.getKind() == Kind.Block) {
                Block block = (Block) referent;
                // Msg.debug(this, "  - Block Address " + block.getAddress());
                if (symbol.getStorageKind() == Symbol.GTIRB_STORAGE_LOCAL) {

                    // Symbol is local to a function what function?

                    long rawAddress = block.getAddress();

                    gtirbFunction function = getFunctionContainingAddress(rawAddress);
                    if (function == null) {
                        Msg.error(
                                this,
                                "No function found for address "
                                        + String.format("0x%X", rawAddress));
                        continue;
                    }

                    // Do I have a namespace yet for this function? If not create one.
                    Namespace localNamespace = namespaceMap.get(function.getName());
                    if (localNamespace == null) {
                        try {
                            localNamespace =
                                    symbolTable.createNameSpace(
                                            null, function.getName(), SourceType.IMPORTED);
                        } catch (Exception e) {
                            Msg.error(
                                    this,
                                    "Error creating namespace for function" + function.getName());
                            continue;
                        }
                        namespaceMap.put(function.getName(), storageUndefined);
                    }
                    // Now get the programs version of the address and add the symbol
                    Address symbolAddress = program.getImageBase().add(block.getAddress());
                    addSymbol(symbol, symbolAddress, program, localNamespace);
                } else {
                    // Not local, treat as global for now
                    // TODO: should check for extern here
                    Address symbolAddress = program.getImageBase().add(block.getAddress());
                    addSymbol(symbol, symbolAddress, program, null);
                }
            } else if (referent.getKind() == Kind.DataObject) {
                DataObject dataObject = (DataObject) referent;
                // Msg.debug(this, "  - Data Object Address " + dataObject.getAddress());
                Address symbolAddress = program.getImageBase().add(dataObject.getAddress());
                addSymbol(symbol, symbolAddress, program, null);
            } else if (referent.getKind() == Kind.Block) {
                Block block = (Block) referent;
                // Msg.debug(this, "  - Block Address " + block.getAddress());
                Address symbolAddress = program.getImageBase().add(block.getAddress());
                addSymbol(symbol, symbolAddress, program, null);
            } else if (referent.getKind() == Kind.ProxyBlock) {
                // Msg.debug(this, "  - Proxy Block");
                ;
            }

            // else {
            //	//Msg.debug(this, "  - Unrecognized referent.");
            // }
        }

        //
        // Process the code blocks
        // Iterate through the Block table in gtirb IR.
        // The blocks have already been loaded into program memory, this operation just marks
        // them as code as opposed to data or other.
        //
        ArrayList<Block> blockList = module.getBlockList();
        for (Block block : blockList) {
            markAsCode(program, block.getAddress(), block.getSize());
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

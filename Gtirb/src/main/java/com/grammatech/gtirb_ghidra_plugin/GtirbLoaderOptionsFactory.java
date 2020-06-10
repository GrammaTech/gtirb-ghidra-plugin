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

import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.util.StringUtilities;
import java.util.List;

public class GtirbLoaderOptionsFactory {

    public static final String PERFORM_RELOCATIONS_NAME =
        "Perform Symbol Relocations";
    static final boolean PERFORM_RELOCATIONS_DEFAULT = true;

    // NOTE: Using too large of an image base can cause problems for relocation
    // processing for some language scenarios which utilize 32-bit relocations.
    // This may be due to an assumed virtual memory of 32-bits.

    public static final String IMAGE_BASE_OPTION_NAME = "Image Base";
    public static final long IMAGE_BASE_DEFAULT = 0x00010000;
    public static final long IMAGE64_BASE_DEFAULT = 0x00100000L;

    public static final String INCLUDE_OTHER_BLOCKS =
        "Import Non-Loaded Data"; // as OTHER overlay blocks
    static final boolean INCLUDE_OTHER_BLOCKS_DEFAULT = true;

    public static final String RESOLVE_EXTERNAL_SYMBOLS_OPTION_NAME =
        "Fixup Unresolved External Symbols";
    public static final boolean RESOLVE_EXTERNAL_SYMBOLS_DEFAULT = true;

    private GtirbLoaderOptionsFactory() {}

    static void addOptions(List<Option> options, ByteProvider provider,
                           LoadSpec loadSpec) throws LanguageNotFoundException {

        // NOTE: add-to-program is not supported

        // options.add(new Option(PERFORM_RELOCATIONS_NAME,
        // PERFORM_RELOCATIONS_DEFAULT, Boolean.class,
        //		Loader.COMMAND_LINE_ARG_PREFIX + "-applyRelocations"));

        // ElfHeader elf =
        // ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE,
        // provider);

        // Important test here for whether binaryu file has a reasonable load
        // address and/or says that it is relocatable. if not and it is
        // relocatable, use 10000 or 100000 depending on 32 bit or 64 bit long
        // imageBase = elf.findImageBase(); if (imageBase == 0 &&
        // (elf.isRelocatable() || elf.isSharedObject())) {
        //		imageBase = elf.is64Bit() ? IMAGE64_BASE_DEFAULT :
        //IMAGE_BASE_DEFAULT;
        // }
        long imageBase = IMAGE64_BASE_DEFAULT;
        AddressSpace defaultSpace =
            loadSpec.getLanguageCompilerSpec().getLanguage().getDefaultSpace();

        String baseOffsetStr = getBaseOffsetString(imageBase, defaultSpace);
        options.add(new Option(IMAGE_BASE_OPTION_NAME, baseOffsetStr,
                               String.class,
                               Loader.COMMAND_LINE_ARG_PREFIX + "-imagebase"));

        // options.add(new Option(INCLUDE_OTHER_BLOCKS,
        // INCLUDE_OTHER_BLOCKS_DEFAULT, Boolean.class,
        //		Loader.COMMAND_LINE_ARG_PREFIX +
        //"-includeOtherBlocks"));

        // options.add(
        //		new Option(RESOLVE_EXTERNAL_SYMBOLS_OPTION_NAME,
        //RESOLVE_EXTERNAL_SYMBOLS_DEFAULT, 		Boolean.class,
        //Loader.COMMAND_LINE_ARG_PREFIX + "-resolveExternalSymbols"));
    }

    private static String getBaseOffsetString(long imageBase,
                                              AddressSpace defaultSpace) {
        long maxOffset =
            defaultSpace.getMaxAddress().getAddressableWordOffset();
        while (Long.compareUnsigned(imageBase, maxOffset) > 0) {
            imageBase >>>= 4;
        }
        String baseOffsetStr = Long.toHexString(imageBase);
        int minNibbles = Math.min(8, defaultSpace.getSize() / 4);
        int baseOffsetStrLen = baseOffsetStr.length();
        if (baseOffsetStrLen < minNibbles) {
            baseOffsetStr = StringUtilities.pad(baseOffsetStr, '0',
                                                minNibbles - baseOffsetStrLen);
        }
        return baseOffsetStr;
    }

    static String validateOptions(LoadSpec loadSpec, List<Option> options) {
        for (Option option : options) {
            String name = option.getName();
            // if (name.equals(PERFORM_RELOCATIONS_NAME)) {
            //	if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
            //		return "Invalid type for option: " + name + " - " +
            //option.getValueClass();
            //	}
            // }
            // else if (name.equals(INCLUDE_OTHER_BLOCKS)) {
            //	if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
            //		return "Invalid type for option: " + name + " - " +
            //option.getValueClass();
            //	}
            // }
            // else if (name.equals(IMAGE_BASE_OPTION_NAME)) {
            if (name.equals(IMAGE_BASE_OPTION_NAME)) {
                if (!String.class.isAssignableFrom(option.getValueClass())) {
                    return "Invalid type for option: " + name + " - " +
                        option.getValueClass();
                }
                String value = (String)option.getValue();
                try {
                    AddressSpace space = loadSpec.getLanguageCompilerSpec()
                                             .getLanguage()
                                             .getDefaultSpace();
                    space.getAddress(Long.parseUnsignedLong(
                        value, 16)); // verify valid address
                } catch (NumberFormatException e) {
                    return "Invalid " + name +
                        " - expecting hexidecimal address offset";
                } catch (AddressOutOfBoundsException e) {
                    return "Invalid " + name + " - " + e.getMessage();
                } catch (LanguageNotFoundException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        return null;
    }

    // static boolean performRelocations(List<Option> options) {
    //		return OptionUtils.getOption(PERFORM_RELOCATIONS_NAME, options,
    //			PERFORM_RELOCATIONS_DEFAULT);
    //	}
    //
    //	static boolean includeOtherBlocks(List<Option> options) {
    //		return OptionUtils.getOption(INCLUDE_OTHER_BLOCKS, options,
    //INCLUDE_OTHER_BLOCKS_DEFAULT);
    //	}

    static boolean hasImageBaseOption(List<Option> options) {
        return OptionUtils.containsOption(IMAGE_BASE_OPTION_NAME, options);
    }

    public static String getImageBaseOption(List<Option> options) {
        return OptionUtils.getOption(IMAGE_BASE_OPTION_NAME, options,
                                     (String)null);
    }
}

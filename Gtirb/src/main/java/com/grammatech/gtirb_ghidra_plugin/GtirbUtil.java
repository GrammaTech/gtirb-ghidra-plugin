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
import com.grammatech.gtirb.Symbol;
import ghidra.program.model.listing.Program;
import java.util.UUID;

public class GtirbUtil {

    public static Symbol getSymbolByReferent(Module module, UUID referentUuid) {
        for (Symbol symbol : module.getSymbols()) {
            if (symbol.hasReferent()) {
                UUID symReferentUuid = symbol.getReferentByUuid();
                if (referentUuid.equals(symReferentUuid)) {
                    return symbol;
                }
            }
        }
        return null;
    }

    public static final boolean isGtIrb(Program program) {
        if (program != null) {
            if (program.getExecutablePath().endsWith(GtirbConstants.GTIRB_EXTENSION)) {
                return true;
            }
        }
        return false;
    }

    public static String getElfSectionType(int sh_type) {
        String retval;
        switch (sh_type) {
            case 0:
                retval = "SHT_NULL";
                break;
            case 1:
                retval = "SHT_PROGBITS";
                break;
            case 2:
                retval = "SHT_SYMTAB";
                break;
            case 3:
                retval = "SHT_STRTAB";
                break;
            case 4:
                retval = "SHT_RELA";
                break;
            case 5:
                retval = "SHT_HASH";
                break;
            case 6:
                retval = "SHT_DYNAMIC";
                break;
            case 7:
                retval = "SHT_NOTE";
                break;
            case 8:
                retval = "SHT_NOBITS";
                break;
            case 9:
                retval = "SHT_REL";
                break;
            case 10:
                retval = "SHT_DYNSYM";
                break;
            case 11:
                retval = "SHLIB";
                break;
                // 12? 13?
            case 14:
                retval = "INIT_ARRAY";
                break;
            case 15:
                retval = "FINI_ARRAY";
                break;
            default:
                retval = String.format("0x%X", sh_type);
                break;
        }
        return retval;
    }
}

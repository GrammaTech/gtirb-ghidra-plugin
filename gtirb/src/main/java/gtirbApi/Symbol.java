/** */
package gtirbApi;

import java.util.UUID;

/** @author tneale */
public class Symbol extends Node {
    private String name;
    private UUID referentUuid;
    private int storageKind;

    public static final int GTIRB_STORAGE_UNDEFINED =
            proto.SymbolOuterClass.StorageKind.Storage_Undefined_VALUE;
    public static final int GTIRB_STORAGE_NORMAL =
            proto.SymbolOuterClass.StorageKind.Storage_Normal_VALUE;
    public static final int GTIRB_STORAGE_STATIC =
            proto.SymbolOuterClass.StorageKind.Storage_Static_VALUE;
    public static final int GTIRB_STORAGE_EXTERN =
            proto.SymbolOuterClass.StorageKind.Storage_Extern_VALUE;
    public static final int GTIRB_STORAGE_LOCAL =
            proto.SymbolOuterClass.StorageKind.Storage_Local_VALUE;

    public Symbol(proto.SymbolOuterClass.Symbol protoSymbol) {

        UUID uuid = Util.byteStringToUuid(protoSymbol.getUuid());
        super.setUuid(uuid);
        super.setKind(Kind.Symbol);
        this.name = protoSymbol.getName();
        this.referentUuid = Util.byteStringToUuid(protoSymbol.getReferentUuid());
        this.storageKind = protoSymbol.getStorageKindValue();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public UUID getReferentUuid() {
        return referentUuid;
    }
    
    public int getStorageKind() {
    	return storageKind;
    }
    
}

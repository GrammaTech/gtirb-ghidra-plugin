/** */
package gtirbApi;

import java.util.UUID;

/** @author tneale */
public class Block extends Node {
    private long address;
    private long size;
    private long decodeMode;

    public Block(proto.BlockOuterClass.Block protoBlock) {
        UUID uuid = Util.byteStringToUuid(protoBlock.getUuid());
        super.setUuid(uuid);
        super.setKind(Kind.Block);
        this.address = protoBlock.getAddress();
        this.size = protoBlock.getSize();
        this.decodeMode = protoBlock.getDecodeMode();
    }

    public long getAddress() {
        return address;
    }

    public void setAddress(long address) {
        this.address = address;
    }

    public long getSize() {
        return size;
    }

    public void setSize(long size) {
        this.size = size;
    }

    public long getDecodeMode() {
        return decodeMode;
    }

    public void setDecodeMode(long decodeMode) {
        this.decodeMode = decodeMode;
    }
}

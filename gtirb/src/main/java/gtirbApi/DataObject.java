/** */
package gtirbApi;

import java.util.UUID;

/** @author tneale */
public class DataObject extends Node {
    private long address;
    private long size;

    public DataObject(proto.DataObjectOuterClass.DataObject protoDataObject) {
        UUID uuid = Util.byteStringToUuid(protoDataObject.getUuid());
        super.setUuid(uuid);
        super.setKind(Kind.DataObject);
        this.address = protoDataObject.getAddress();
        this.size = protoDataObject.getSize();
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
}

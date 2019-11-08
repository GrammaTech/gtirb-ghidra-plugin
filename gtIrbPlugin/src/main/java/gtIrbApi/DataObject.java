/** */
package gtIrbApi;

import java.util.UUID;

/** @author tneale */
public class DataObject extends Node {
    private long address;
    private long size;

    public DataObject(proto.DataObjectOuterClass.DataObject protoDataObject) {
        UUID uuid = Util.byteStringToUuid(protoDataObject.getUuid());
        //    	byte[] uuidByteArray = protoDataObject.getUuid().toByteArray();
        //    	ByteBuffer bb = ByteBuffer.wrap(uuidByteArray);
        //    	UUID uuid = new UUID(bb.getLong(), bb.getLong());
        super.setUuid(uuid);
        super.setKind(Kind.DataObject);
        this.address = protoDataObject.getAddress();
        this.size = protoDataObject.getSize();
        // System.out.println("Created GTIRB API data object from data object at " +
        // protoDataObject.getAddress() +
        //		" UUID " + uuid.toString());

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

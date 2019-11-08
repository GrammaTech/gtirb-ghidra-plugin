/** */
package gtIrbApi;

import java.nio.ByteBuffer;
import java.util.UUID;

/** @author tneale */
public class Util {

    public static UUID nilUuid = new UUID(0, 0);

    public static UUID byteStringToUuid(com.google.protobuf.ByteString byteString) {
        if (byteString == com.google.protobuf.ByteString.EMPTY) {
            return new UUID(0, 0);
        }
        byte[] uuidByteArray = byteString.toByteArray();
        ByteBuffer bb = ByteBuffer.wrap(uuidByteArray);
        return new UUID(bb.getLong(), bb.getLong());
    }
}

/** */
package gtIrbApi;

import java.util.UUID;

/** @author tneale */
public class ProxyBlock extends Node {

    public ProxyBlock(proto.ProxyBlockOuterClass.ProxyBlock protoProxyBlock) {
        UUID uuid = Util.byteStringToUuid(protoProxyBlock.getUuid());
        super.setUuid(uuid);
        super.setKind(Kind.ProxyBlock);
        // System.out.println("Created GTIRB API proxy block from proxy block");
    }
}

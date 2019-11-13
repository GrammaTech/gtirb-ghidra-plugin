/** */
package gtirbApi;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/** @author tneale */
public class Node {
    UUID uuid;
    Kind kind;
    private static Map<UUID, Node> uuid_cache = new HashMap<UUID, Node>();

    public Node() {
        // To match C++, a random UUID would be assigned here.
        // However, as I am only working with objects that have already been created, this
        //  would only have to be un-done and replaced with the correct UUID.
    }

    public Node getByUuid(UUID uuid) {
        return uuid_cache.get(uuid);
    }

    public Node setUuid(UUID uuid) {
        return uuid_cache.put(uuid, this);
    }

    public Kind getKind() {
        return this.kind;
    }

    public void setKind(Kind kind) {
        this.kind = kind;
    }

    public int getCacheSize() {
        return uuid_cache.size();
    }
}

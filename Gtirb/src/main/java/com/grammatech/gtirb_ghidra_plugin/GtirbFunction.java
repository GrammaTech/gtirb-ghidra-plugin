/** */
package com.grammatech.gtirb_ghidra_plugin;

import java.util.UUID;

/** */
public class GtirbFunction {

    private String name;
    private long address;
    private int size;
    private UUID uuid;

    public GtirbFunction(String name, long address, int size, UUID uuid) {
        setName(name);
        setAddress(address);
        setSize(size);
        setUuid(uuid);
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public long getAddress() {
        return this.address;
    }

    public void setAddress(long address) {
        this.address = address;
    }

    public int getSize() {
        return this.size;
    }

    public void setSize(int size) {
        this.size = size;
    }

    public UUID getUuid() {
        return this.uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }
}

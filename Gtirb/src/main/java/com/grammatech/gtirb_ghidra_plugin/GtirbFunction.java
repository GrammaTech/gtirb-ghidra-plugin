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

    public String getName() { return this.name; }

    public void setName(String name) { this.name = name; }

    public long getAddress() { return this.address; }

    public void setAddress(long address) { this.address = address; }

    public int getSize() { return this.size; }

    public void setSize(int size) { this.size = size; }

    public UUID getUuid() { return this.uuid; }

    public void setUuid(UUID uuid) { this.uuid = uuid; }
}

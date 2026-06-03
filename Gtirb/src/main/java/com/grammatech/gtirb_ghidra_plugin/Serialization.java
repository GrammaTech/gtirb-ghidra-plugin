/*
 *  Copyright (C) 2020 GrammaTech, Inc.
 *
 *  This code is licensed under the MIT license. See the LICENSE file in the
 *  project root for license terms.
 *
 */
package com.grammatech.gtirb_ghidra_plugin;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Simple sequential binary reader for little-endian byte buffers.
 * This replaces the Serialization class that was removed from GTIRB 2.x.
 */
public class Serialization {
    private final ByteBuffer buf;

    public Serialization(byte[] bytes) {
        buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
    }

    public int getRemaining() {
        return buf.remaining();
    }

    public long getLong() {
        return buf.getLong();
    }

    public int getInt() {
        return buf.getInt();
    }

    public short getShort() {
        return buf.getShort();
    }

    public byte getByte() {
        return buf.get();
    }
}

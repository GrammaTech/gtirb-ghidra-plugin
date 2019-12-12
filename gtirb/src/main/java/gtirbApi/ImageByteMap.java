package gtirbApi;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

// import ghidra.util.Msg;

public final class ImageByteMap extends Node {

    private List<Region> regionList;
    private long minAddress;
    private long maxAddress;

    public ImageByteMap(proto.ImageByteMapOuterClass.ImageByteMap protoImageByteMap) {
        UUID uuid = Util.byteStringToUuid(protoImageByteMap.getUuid());
        super.setUuid(uuid);
        this.regionList = new ArrayList<Region>();
        this.maxAddress = -1;
        this.minAddress = -1;
    }

    boolean addRegion(Region region) {

        // Check that the range is valid
        if ((region.getStartAddress() < 0) || (region.getLength() == 0)) {
            // Msg.error(this, "addRegion: invalid range");
            return false;
        }

        // Check if this is the first range being added, if so add it and return
        if (this.regionList.size() < 1) {
            this.minAddress = region.getStartAddress();
            this.maxAddress = this.minAddress + region.getLength() - 1;
            this.regionList.add(region);
            // Msg.debug(this, "Added first region to list.");
            return true;
        }

        // All this is to set the insert position of the new address range
        int insertPosition = -1;
        for (Region r : regionList) {
            if (region.getStartAddress() < r.getStartAddress()) {
                insertPosition = regionList.indexOf(r);
                break;
            }
        }
        if (insertPosition == -1) {
            insertPosition = this.regionList.size();
        }

        // If insert position is not "first", check for overlap with preceding Range
        if (insertPosition > 0) {
            int belowPosition = insertPosition - 1;
            Region belowRange = this.regionList.get(belowPosition);
            if ((belowRange.getStartAddress() + belowRange.getLength())
                    > region.getStartAddress()) {
                // Msg.error(this, "addRegion: overlapping regions not permitted");
                return false;
            }
            // If regions are contiguous, combine them
            if ((belowRange.getStartAddress() + belowRange.getLength())
                    == region.getStartAddress()) {
                // Msg.debug(this, "addRegion: coelescing regions");
                byte[] replacement = new byte[belowRange.getLength() + region.getLength()];
                System.arraycopy(belowRange.getBytes(), 0, replacement, 0, belowRange.getLength());
                System.arraycopy(
                        region.getBytes(),
                        0,
                        replacement,
                        belowRange.getLength(),
                        region.getLength());
                Region replacementRange = new Region(belowRange.getStartAddress(), replacement);
                this.regionList.set(this.regionList.indexOf(belowRange), replacementRange);
            }
        }

        // If insert position is not "last", check for overlap with following Range
        if (insertPosition < this.regionList.size() - 1) {
            int abovePosition = insertPosition + 1;
            Region aboveRange = this.regionList.get(abovePosition);
            if ((region.getStartAddress() + region.getLength()) > aboveRange.getStartAddress()) {
                // Msg.error(this, "addRegion: overlapping regions not permitted");
                return false;
            }
            // If regions are contiguous, combine them
            if ((region.getStartAddress() + region.getLength()) == aboveRange.getStartAddress()) {
                // Msg.debug(this, "addRegion: coelescing regions");
                byte[] replacement = new byte[region.getLength() + aboveRange.getLength()];
                System.arraycopy(region.getBytes(), 0, replacement, 0, region.getLength());
                System.arraycopy(
                        aboveRange.getBytes(),
                        0,
                        replacement,
                        region.getLength(),
                        aboveRange.getLength());
                Region replacementRange = new Region(aboveRange.getStartAddress(), replacement);
                this.regionList.set(this.regionList.indexOf(aboveRange), replacementRange);
            }
        }

        // no overlap, go ahead
        this.regionList.add(insertPosition, region);

        int size = this.regionList.size();
        Region first = this.regionList.get(0);
        Region last = this.regionList.get(size - 1);
        this.minAddress = first.getStartAddress();
        this.maxAddress = last.getStartAddress() + last.getLength() - 1;

        return true;
    }

    int regionContains(long startAddress, int size) {
        long endAddress = startAddress + size - 1;
        for (Region range : this.regionList) {
            if ((range.contains(startAddress)) && range.contains(endAddress))
                return this.regionList.indexOf(range);
        }
        return -1;
    }

    byte[] getBytes(long startAddress, int size) {
        int regionNumber = regionContains(startAddress, size);

        if (regionNumber < 0) return null;

        Region region = regionList.get(regionNumber);
        byte[] replacement = new byte[size];
        System.arraycopy(
                region.getBytes(),
                (int) (startAddress - region.getStartAddress()),
                replacement,
                0,
                size);
        return replacement;
    }
}

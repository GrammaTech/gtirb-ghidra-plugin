package gtIrbApi;

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
            Msg.error(this, "addRegion: invalid range");
            return false;
        }

        // System.out.println("Adding new region:");
        // System.out.println("From " + String.format("0x%08X", region.getStartAddress())
        //	+ " To " + String.format("0x%08X", region.getStartAddress() + region.getLength() -1)
        //	+ "     size: " + String.format("%d", region.getLength())
        //	+ " (" + String.format("0x%x)", region.getLength()));

        // Check if this is the first range being added, if so add it and return
        if (this.regionList.size() < 1) {
            this.minAddress = region.getStartAddress();
            this.maxAddress = this.minAddress + region.getLength() - 1;
            this.regionList.add(region);
            Msg.debug(this, "Added first region to list.");
            return true;
        }

        // All this is to set the insert position of the new address range
        int insertPosition = -1;
        // ListIterator<Region> listIter = this.regionList.listIterator();
        // while (listIter.hasNext()) {
        //	Region thisRange = listIter.next();
        //	if (region.getStartAddress() < thisRange.getStartAddress()) {
        //		insertPosition = this.regionList.indexOf(thisRange);
        //		break;
        //	}
        // }
        for (Region r : regionList) {
            if (region.getStartAddress() < r.getStartAddress()) {
                insertPosition = regionList.indexOf(r);
                break;
            }
        }
        if (insertPosition == -1) {
            insertPosition = this.regionList.size();
        }

        // System.out.println("Calculated insert position: " + insertPosition);

        // If insert position is not "first", check for overlap with preceding Range
        if (insertPosition > 0) {
            int belowPosition = insertPosition - 1;
            Region belowRange = this.regionList.get(belowPosition);
            if ((belowRange.getStartAddress() + belowRange.getLength())
                    > region.getStartAddress()) {
                Msg.error(this, "addRegion: overlapping regions not permitted");
                return false;
            }
            // If regions are contiguous, combine them
            if ((belowRange.getStartAddress() + belowRange.getLength())
                    == region.getStartAddress()) {
                Msg.debug(this, "addRegion: coelescing regions");
                byte[] replacement = new byte[belowRange.getLength() + region.getLength()];
                Msg.debug(this, lowRange.getBytes(), 0, replacement, 0, belowRange.getLength());
                Msg.debug(
                        this,
                        gion.getBytes(),
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
                Msg.error(this, "addRegion: overlapping regions not permitted");
                return false;
            }
            // If regions are contiguous, combine them
            if ((region.getStartAddress() + region.getLength()) == aboveRange.getStartAddress()) {
                Msg.debug(this, "addRegion: coelescing regions");
                byte[] replacement = new byte[region.getLength() + aboveRange.getLength()];
                Msg.debug(this, gion.getBytes(), 0, replacement, 0, region.getLength());
                Msg.debug(
                        this,
                        oveRange.getBytes(),
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

        // System.out.println("addRegion: size " + size);
        // System.out.println("addRegion: minAddress " + this.minAddress);
        // System.out.println("addRegion: maxAddress " + this.maxAddress);

        return true;
    }

    void printImageByteMap() {
        // ListIterator<Region> listIter = regionList.listIterator();
        // while (listIter.hasNext()) {
        //	Region thisRange = listIter.next();
        //	System.out.println("MemRange " + regionList.indexOf(thisRange) + " addr " +
        // thisRange.getStartAddress());
        // }
        for (Region range : this.regionList) {
            long startAddr = range.getStartAddress();
            int length = range.getLength();
            long endAddr = startAddr + length - 1;
            Msg.debug(
                    this,
                    "From "
                            + String.format("0x%08X", startAddr)
                            + " To "
                            + String.format("0x%08X", endAddr)
                            + "     size: "
                            + String.format("%d", length)
                            + " ("
                            + String.format("0x%x)", length));
        }
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

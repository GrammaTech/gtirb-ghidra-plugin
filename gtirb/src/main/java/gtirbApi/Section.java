package gtirbApi;

// import ghidra.util.Msg;

public class Section {
    private String name;
    private long address;
    private long size;

    public Section(proto.SectionOuterClass.Section protoSection) {
        this.setName(protoSection.getName());
        this.setAddress(protoSection.getAddress());
        this.setSize(protoSection.getSize());
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
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

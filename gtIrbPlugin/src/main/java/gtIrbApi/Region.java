package gtIrbApi;

public final class Region {
	private long startAddress;
	private byte[] bytes;
	
	public Region(long startAddress, byte[] bytes) {
		this.startAddress = startAddress;
		this.bytes = bytes;
	}
	
	public long getStartAddress() {
		return startAddress;
	}
	
	public void setStartAddress(long startAddress) {
		this.startAddress = startAddress;
	}
	
	public byte[] getBytes() {
		return bytes;
	}
	
	public void setBytes(byte[] bytes) {
		this.bytes = bytes;
	}

	public int getLength() {
		return bytes.length;
	}
	
	public boolean contains (long address) {
		if ((address >= this.startAddress) && (address < (this.startAddress + this.bytes.length)))
			return true;
		return false;
	}
}


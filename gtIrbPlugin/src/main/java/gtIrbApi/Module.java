package gtIrbApi;

import java.util.ArrayList;
import java.util.List;

import ghidra.util.Msg;
import com.google.protobuf.ByteString;

public class Module {
	
	private proto.ModuleOuterClass.Module protoModule;
	private ImageByteMap imageByteMap;
    private ArrayList<Section> sectionList;
	
	public Module(proto.ModuleOuterClass.Module protoModule) {
	    this.protoModule = protoModule;
	    this.imageByteMap = new ImageByteMap();
		this.sectionList = new ArrayList<Section>();
	    Msg.debug(this, "Created GTIRB API module from proto module " + protoModule.getName());
	}
	
	public boolean initializeImageByteMap () {

        // From module, get imageByteMap
        //   From imageByteMap, get byteMap
        //      From byteMap get list of region
        //         For every region, get data
        //             from data get byte array
    	proto.ImageByteMapOuterClass.ImageByteMap ibm = protoModule.getImageByteMap();
    	proto.ByteMapOuterClass.ByteMap bm = ibm.getByteMap();
    	List<proto.ByteMapOuterClass.Region> regionList = bm.getRegionsList();
    	for (proto.ByteMapOuterClass.Region r : regionList) {
    		long startAddress = r.getAddress();
    		ByteString d = r.getData();
    		byte[] byteArray = d.toByteArray();
    		Region newRange = new Region(startAddress, byteArray);
            imageByteMap.addRegion(newRange);
    	}
    	imageByteMap.printImageByteMap();
        return true;       
	}
	
	public boolean initializeSectionList () {

        // Get proto Section list
        // For each section, add to sectionList in this class
		List<proto.SectionOuterClass.Section> protoSectionList = protoModule.getSectionsList();
		for (proto.SectionOuterClass.Section protoSection: protoSectionList) {
			Section newSection = new Section(protoSection);
			sectionList.add(newSection);			
		}
        return true;       
	}

	public byte[] getBytes(long startAddress, int size) {
		return imageByteMap.getBytes(startAddress, size);
	}

	public ArrayList<Section> getSections() {
		return this.sectionList;
	}
}

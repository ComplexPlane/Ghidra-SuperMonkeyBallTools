package supermonkeyballtools.region;

import supermonkeyballtools.addr.DeltaAddr;
import supermonkeyballtools.addr.GhidraAddr;
import supermonkeyballtools.addr.RamAddr;

public class Region {
    public RegionType regionType;
    public String name;
    public RelSection relSection;
    public DeltaAddr length;
    public GhidraAddr ghidraAddr; // No Ghidra address if e.g. imported pracmod/wsmod region
    public RamAddr ramAddr;

    /**
     * @brief Create a memory region
     */
    public Region(RegionType regionType,
                            String name,
                            RelSection relSection,
                            DeltaAddr length,
                            GhidraAddr ghidraAddr,
                            RamAddr ramAddr)
                           
    {
        this.regionType = regionType;
        this.name = name;
        this.relSection = relSection;
        this.length = length;
        this.ghidraAddr = ghidraAddr;
        this.ramAddr = ramAddr;
    }

    public String getModuleName() {
        if (isModule()) {
            return name.substring(0, name.lastIndexOf("."));
        }

        throw new RuntimeException("Cannot get module name; this memory region does not correspond to a module");
    }

    public boolean isModule() {
        return regionType == RegionType.INITIALIZED || regionType == RegionType.BSS;
    }

    public boolean containsGhidraAddr(GhidraAddr addr) {
        if (this.ghidraAddr == null) {
            return false;
        }
        boolean lowerBound = addr.compareTo(this.ghidraAddr) != -1;
        boolean upperBound = addr.compareTo(this.ghidraAddr.add(this.length)) == -1;
        return lowerBound && upperBound;
    }

    public boolean containsRamAddr(RamAddr addr) {
        if (this.ramAddr == null) {
            return false;
        }
        boolean lowerBound = addr.compareTo(this.ramAddr) != -1;
        boolean upperBound = addr.compareTo(this.ramAddr.add(this.length)) == -1;
        return lowerBound && upperBound;
    }

    @Override
    public String toString() {
        return name;
    }
}

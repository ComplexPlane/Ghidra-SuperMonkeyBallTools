package supermonkeyballtools;

import ghidra.program.model.address.Address;

import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;

public class GameMemoryRegion {
    public RegionType regionType;
    public String name;
    public RelSection relSection;
    public long length;
    public Long ghidraAddr; // No Ghidra address if e.g. imported pracmod/wsmod region
    public long ramAddr;
    public Long fileAddr; // No file if BSS

    /**
     * @brief Create a memory region
     */
    public GameMemoryRegion(RegionType regionType,
                            String name,
                            RelSection relSection,
                            long length,
                            Long ghidraAddr,
                            long ramAddr,
                            Long fileAddr)
    {
        this.regionType = regionType;
        this.name = name;
        this.relSection = relSection;
        this.length = length;
        this.ghidraAddr = ghidraAddr;
        this.ramAddr = ramAddr;
        this.fileAddr = fileAddr;
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

    public boolean isAddressInRegion(long addr) {
        if (ghidraAddr == null) {
            return false;
        }
        return addr >= ghidraAddr && addr < (ghidraAddr + length);
    }

    public boolean isRamAddressInRegion(long addr) {
        long delta = addr - ramAddr;
        return delta >= 0 && delta < length;
    }

    @Override
    public String toString() {
        return name;
    }
}

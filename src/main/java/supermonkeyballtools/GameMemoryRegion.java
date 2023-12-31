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
    public long ghidraAddr;
    public long ramAddr;
    public Long fileAddr;

    /**
     * @brief Create a memory region
     */
    public GameMemoryRegion(RegionType regionType,
                            String name,
                            RelSection relSection,
                            long length,
                            long ghidraAddr,
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
        return addr >= ghidraAddr && addr < (ghidraAddr + length);
    }

    public boolean isRamAddressInRegion(long addr) {
        long delta = addr - ramAddr;
        return delta >= 0 && delta < length;
    }

    @Override
    public String toString() {
        return name;
//        return String.format("%s: len: %08X, ghidra: %08X, ram: %08X", name, length, ghidraAddr, ramAddr);
    }
}

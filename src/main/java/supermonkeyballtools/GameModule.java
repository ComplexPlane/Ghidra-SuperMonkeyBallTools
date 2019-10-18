package supermonkeyballtools;

import ghidra.program.model.address.Address;

public class GameModule {
    private String baseName;
    private Address startAddress;
    private Address endAddress;

    public GameModule(String baseName) {
        this.baseName = baseName;
    }

    public boolean isAddressInModule(Address addr) {
        return startAddress.getOffset() <= addr.getOffset() &&
            addr.getOffset() <= endAddress.getOffset();
    }

    public void setBaseName(String baseName) {
        this.baseName = baseName;
    }

    public String getBaseName() {
        return baseName;
    }

    public void setStartAddress(Address startAddress) {
        this.startAddress = startAddress;
    }

    public Address getStartAddress() {
        return startAddress;
    }

    public void setEndAddress(Address endAddress) {
        this.endAddress = endAddress;
    }

    public Address getEndAddress() {
        return endAddress;
    }

    @Override
    public String toString() {
        return String.format("<GameModule: '%s' %s - %s>", baseName, startAddress, endAddress);
    }
}

package supermonkeyballtools.addr;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public class GhidraAddr implements Comparable<GhidraAddr> {
    public GhidraAddr(long value) {
        this.value = value;
    }

    protected final long value;

    public GhidraAddr add(DeltaAddr delta) {
        return new GhidraAddr(this.value + delta.value);
    }

    public DeltaAddr sub(GhidraAddr other) {
        return new DeltaAddr(this.value - other.value);
    }

    public String toString() {
        return String.format("%08X", this.value);
    }

    public Address toAddress(AddressSpace addressSpace) {
        return addressSpace.getAddress(this.value);
    }

    @Override
    public int compareTo(GhidraAddr other) {
        return Long.compare(this.value, other.value);
    }
}

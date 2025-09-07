package supermonkeyballtools.addr;

public class RamAddr implements Comparable<RamAddr> {
    public RamAddr(long value) {
        this.value = value;
    }

    protected final long value;

    public RamAddr add(DeltaAddr delta) {
        return new RamAddr(this.value + delta.value);
    }

    public DeltaAddr sub(RamAddr other) {
        return new DeltaAddr(this.value - other.value);
    }

    public String toString() {
        return String.format("0x%08X", this.value);
    }

    @Override
    public int compareTo(RamAddr other) {
        return Long.compare(this.value, other.value);
    }
}

package supermonkeyballtools.addr;

public class GhidraAddr {
    GhidraAddr(long value) {
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
        return String.format("0x%08X", this.value);
    }
}

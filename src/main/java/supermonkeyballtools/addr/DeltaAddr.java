package supermonkeyballtools.addr;

public class DeltaAddr {
    public DeltaAddr(long value) {
        this.value = value;
    }

    protected final long value;

    public String toString() {
        return String.format("0x%08X", this.value);
    }
}

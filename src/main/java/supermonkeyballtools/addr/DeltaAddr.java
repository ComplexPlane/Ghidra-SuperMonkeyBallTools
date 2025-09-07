package supermonkeyballtools.addr;

public class DeltaAddr implements Comparable<DeltaAddr> {
    public DeltaAddr(long value) {
        this.value = value;
    }

    protected final long value;

    public String toString() {
        return String.format("0x%08X", this.value);
    }

    @Override
    public int compareTo(DeltaAddr other) {
        return Long.compare(this.value, other.value);
    }
}

package supermonkeyballtools.addr;

public class FileAddr {
    FileAddr(long value) {
        this.value = value;
    }

    protected final long value;

    public FileAddr add(DeltaAddr delta) {
        return new FileAddr(this.value + delta.value);
    }

    public DeltaAddr sub(FileAddr other) {
        return new DeltaAddr(this.value - other.value);
    }   

    public String toString() {
        return String.format("0x%08X", this.value);
    }
}

package supermonkeyballtools.region;
public class RelSection {
    public final int moduleId;
    public final int sectionIdx;

    public RelSection(int moduleId, int sectionId) {
        this.moduleId = moduleId;
        this.sectionIdx = sectionId;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        RelSection other = (RelSection) obj;
        return moduleId == other.moduleId && sectionIdx == other.sectionIdx;
    }
}

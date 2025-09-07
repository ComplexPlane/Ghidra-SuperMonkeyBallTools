package supermonkeyballtools.export;

import java.util.ArrayList;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import supermonkeyballtools.addr.DeltaAddr;
import supermonkeyballtools.addr.GhidraAddr;
import supermonkeyballtools.addr.RamAddr;
import supermonkeyballtools.region.Region;
import supermonkeyballtools.region.RegionIndex;

public class SymbolExport {
    public static String generateSymbolMap(Program program, boolean mergeHeaps) {
        // Always use vanilla regions
        RegionIndex regionIndex = new RegionIndex();

        ArrayList<String> symbolStrs = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getSymbolIterator()) {
            GhidraAddr ghidraAddr = new GhidraAddr(symbol.getAddress().getOffset());
            Region region = regionIndex.getRegionContainingGhidraAddr(ghidraAddr);
            if (region != null) {
                if (region.relSection != null && mergeHeaps) {
                    DeltaAddr delta = ghidraAddr.sub(region.ghidraAddr);
                    // Export symbol as section offset
                    symbolStrs.add(String.format("%X,%X,%s:%s",
                            region.relSection.moduleId, region.relSection.sectionIdx, delta.toString(),
                            symbol.getName()));
                } else {
                    // Export symbol as global address (DOL, 0xE0000000 range, non merge-heaps)
                    RamAddr ramAddr = regionIndex.ghidraAddrToRam(ghidraAddr);
                    symbolStrs.add(String.format("%s:%s", ramAddr.toString(), symbol.getName()));
                }
            }
        }
        return String.join("\n", symbolStrs);
    }
}

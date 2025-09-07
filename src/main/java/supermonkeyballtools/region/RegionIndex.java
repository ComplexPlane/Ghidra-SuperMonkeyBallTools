package supermonkeyballtools.region;

import java.util.ArrayList;
import java.util.HashSet;

import com.google.gson.Gson;

import ghidra.app.script.AskDialog;
import ghidra.util.Msg;
import supermonkeyballtools.addr.DeltaAddr;
import supermonkeyballtools.addr.GhidraAddr;
import supermonkeyballtools.addr.RamAddr;
import supermonkeyballtools.ui.SuperMonkeyBallToolsPlugin;

public class RegionIndex {
    private ArrayList<Region> currentRegions;

    private static class JsonRegion {
        public String name;
        public int moduleId;
        public int sectionIdx;
        public boolean isBss;
        public long ramAddr;
        public long size;
    }

    // Vanilla regions
    public RegionIndex() {
        ArrayList<Region> regions = VanillaRegions.getStaticRegions();
        regions.addAll(VanillaRegions.getDynamicRegions());
        this.currentRegions = regions;
    }
    
    // Imported regions
    public RegionIndex(String jsonContents) {
        ArrayList<Region> regions = VanillaRegions.getStaticRegions();
        ArrayList<Region> vanillaDynamicRegions = VanillaRegions.getDynamicRegions();

        Gson gson = new Gson();
        JsonRegion[] jsonRegions = gson.fromJson(jsonContents, JsonRegion[].class);
        HashSet<Region> unmatchedVanillaRegions = new HashSet<>(vanillaDynamicRegions);

        for (JsonRegion jsonRegion : jsonRegions) {
            // Create partial new region from JSON region
            Region newRegion = new Region(
                jsonRegion.isBss ? RegionType.BSS : RegionType.INITIALIZED,
                jsonRegion.name,
                new RelSection(jsonRegion.moduleId, jsonRegion.sectionIdx),
                new DeltaAddr(jsonRegion.size),
                null, // Ghidra address, to fill in later
                new RamAddr(jsonRegion.ramAddr)
            );

            // Match new region with a vanilla dynamic region to determine Ghidra address
            for (Region vanillaDynamicRegion : vanillaDynamicRegions) {
                if (vanillaDynamicRegion.relSection != null && 
                    vanillaDynamicRegion.relSection.equals(newRegion.relSection)) {
                    newRegion.regionType = vanillaDynamicRegion.regionType;
                    newRegion.ghidraAddr = vanillaDynamicRegion.ghidraAddr;
                    unmatchedVanillaRegions.remove(vanillaDynamicRegion);
                    break;
                }
            }

            regions.add(newRegion);
        }
        
        // Add unmatched vanilla regions without a RAM address
        for (Region vanillaRegion : unmatchedVanillaRegions) {
            Region newRegion = new Region(
                vanillaRegion.regionType,
                vanillaRegion.name,
                vanillaRegion.relSection,
                vanillaRegion.length,
                vanillaRegion.ghidraAddr,
                null // Unknown RAM address
            );
            regions.add(newRegion);
        }

        this.currentRegions = regions;
    }

    public GhidraAddr ramToGhidraAddr(RamAddr ramAddr) {
        // Generate list of candidate memory regions
        ArrayList<Region> ramRegions = new ArrayList<>();
        for (Region region : currentRegions) {
            if (region.containsRamAddr(ramAddr)) {
                ramRegions.add(region);
            }
        }

        Region region = null;
        if (ramRegions.size() == 0) {
            Msg.showError(
                    SuperMonkeyBallToolsPlugin.class,
                    null,
                    "Error: no region found",
                    String.format("No region found for RAM address 0x%s", ramAddr.toString()));

        } else if (ramRegions.size() == 1) {
            region = ramRegions.get(0);

        } else {
            AskDialog<Region> dialog = new AskDialog<>(
                    null,
                    "Pick region",
                    String.format(
                            "Could not determine region for address 0x%s (region is loaded in an additional REL) - Please pick the loaded region",
                            ramAddr.toString()
                    ),
                    AskDialog.STRING,
                    ramRegions,
                    null
            );
            if (!dialog.isCanceled()) {
                region = dialog.getChoiceValue();
            }
        }

        if (region == null) {
            return null;
        }
        
        if (region.ghidraAddr == null) {
            Msg.showInfo(
                SuperMonkeyBallToolsPlugin.class,
                null, 
                String.format("Region '%s' detected, but not present in Ghidra", region.name),
                String.format("The entered address was found in region '%s', but this region is not present in this Ghidra decompilation.", region.name));
            return null;
        }

        return region.ghidraAddr.add(ramAddr.sub(region.ramAddr));
    }

    public RamAddr ghidraAddrToRam(GhidraAddr addr) {
        Region region = getRegionContainingGhidraAddr(addr);
        if (region != null && region.ghidraAddr != null && region.ramAddr != null) {
            return region.ramAddr.add(addr.sub(region.ghidraAddr));
        }
        return null;
    }

    public Region getRegionContainingGhidraAddr(GhidraAddr addr) {
        for (Region region : currentRegions) {
            if (region.containsGhidraAddr(addr)) {
                return region;
            }
        }
        return null;
    }
}

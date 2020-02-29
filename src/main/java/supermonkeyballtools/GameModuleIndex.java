package supermonkeyballtools;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import ghidra.app.script.AskDialog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;

public class GameModuleIndex {
    private static final long MAIN_LOOP_REL_RAM_OFFSET = 0x80270100L; // Always loaded
    private static final long MAIN_LOOP_REL_GHIDRA_OFFSET = 0x80199fa0L;
    private static final long ADDITIONAL_REL_OFFSET = 0x808F3FE0L; // Loaded REL dependent on game mode

    private List<GameMemoryRegion> regions;

    // Cache a single Program's memory regions
    // Not initialized in constructor because currentProgram is invalid in constructor of
    // SuperMonkeyBallToolsPlugin class
    // Perhaps it's not the responsibility of this class to lazily-initialize itself though
    private Program program;

    public List<GameMemoryRegion> getProgramMemoryRegions() {
        return regions;
    }

    private void ensureRegionMemoryList(Program program) {
        if (program == this.program) return;

        this.program = program;
        regions = new ArrayList<>();

        // Build initial list without things like RAM location filled in
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            RegionType regionType;
            String name = block.getName();

            if (name.startsWith("MAIN_") || name.startsWith("mkb2.")) {
                if (name.contains("uninitialized")) {
                    regionType = RegionType.HEAP;
                } else {
                    regionType = RegionType.INITIALIZED;
                }
            } else {
                regionType = RegionType.HARDWARE;
            }

            regions.add(new GameMemoryRegion(
                    regionType,
                    name,
                    block.getEnd().getOffset() - block.getStart().getOffset() + 1,
                    block.getStart().getOffset(),
                    0,
                    null));
        }

        // Compute the approximate RAM address of each block
        String lastModuleName = null;
        long lastModuleStart = 0;
        for (GameMemoryRegion region : regions) {
            if (region.regionType == RegionType.HARDWARE) {
                region.ramAddr = region.ghidraAddr;

            } else if (region.regionType == RegionType.INITIALIZED) {
                String moduleName = region.getModuleName();

                if (!moduleName.equals(lastModuleName)) {
                    lastModuleName = moduleName;
                    lastModuleStart = region.ghidraAddr;
                }

                switch (moduleName) {
                    case "MAIN_":
                        region.ramAddr = region.ghidraAddr;
                        break;

                    case "mkb2.main_loop_":
                        region.ramAddr = region.ghidraAddr - MAIN_LOOP_REL_GHIDRA_OFFSET + MAIN_LOOP_REL_RAM_OFFSET;
                        break;

                    default:
                        region.ramAddr = region.ghidraAddr - lastModuleStart + ADDITIONAL_REL_OFFSET;
                        break;
                }
            }
        }

        // Make some adjustments, y'know
        for (GameMemoryRegion region : regions) {
            switch (region.name) {
                case "mkb2.main_loop_.uninitialized0":
                    region.ramAddr = 0x8054c8e0L;
                    break;
                case "mkb2.main_game_.uninitialized0":
                    region.ramAddr = 0x8097f4a0L;
                    break;
                case "mkb2.sel_ngc_.uninitialized0":
                    region.ramAddr = 0x80949ca0L;
                    break;
                case "mkb2.rel_mini_bowling_.uninitialized0":
                    region.ramAddr = 0x8091e840L;
                    break;
                case "mkb2.rel_mini_billiards_.uninitialized0":
                    region.ramAddr = 0x80942dc0L;
                    break;
                case "mkb2.race2_.uninitialized0":
                    region.ramAddr = 0x809234e0L;
                    break;
                case "mkb2.golf2_.uninitialized0":
                    region.ramAddr = 0x80942ce0L;
                    break;
                case "mkb2.mini_fight2_.uninitialized0":
                    region.ramAddr = 0x80939ac0L;
                    break;
                case "mkb2.pilot2_.uninitialized0":
                    region.ramAddr = 0x80910bc0L;
                    break;
                case "mkb2.boat_.uninitialized0":
                    region.ramAddr = 0x80928980L;
                    break;
                case "mkb2.shooting_.uninitialized0":
                    region.ramAddr = 0x809a5740L;
                    break;
                case "mkb2.rel_mini_futsal_.uninitialized0":
                    region.ramAddr = 0x809369a0L;
                    break;
                case "mkb2.dogfight_.uninitialized0":
                    region.ramAddr = 0x809150c0L;
                    break;
                case "mkb2.baseball_.uninitialized0":
                    region.ramAddr = 0x809b06a0L;
                    break;
                case "mkb2.tennis_.uninitialized0":
                    region.ramAddr = 0x8092caa0L;
                    break;
                case "mkb2.exoption_.uninitialized0":
                case "mkb2.rel_sample_.uninitialized0":
                case "mkb2.test_mode_.uninitialized0":
                case "mkb2.option_.uninitialized0":
                case "mkb2.sel_stage_.uninitialized0":
                    // Unknown where these are, so just eliminate them
                    region.length = 0;
                    break;
            }
        }
    }

    public Long ramToAddressUser(Program program, Address addr) {
        ensureRegionMemoryList(program);

        long offset = addr.getOffset();

        // Generate list of candidate memory regions
        List<GameMemoryRegion> ramRegions = new ArrayList<>();
        for (GameMemoryRegion region : regions) {
            if (region.isRamAddressInRegion(offset)) {
                ramRegions.add(region);
            }
        }

        if (ramRegions.size() == 0) {
            Msg.showError(
                    SuperMonkeyBallToolsPlugin.class,
                    null,
                    "Error: no region found",
                    String.format("No region found for RAM address 0x%08x", offset));

            return null;

        } else if (ramRegions.size() == 1) {
            GameMemoryRegion region = ramRegions.get(0);
            return offset - region.ramAddr + region.ghidraAddr;

        } else {
            AskDialog<GameMemoryRegion> dialog = new AskDialog<>(
                    null,
                    "Pick region",
                    String.format(
                            "Could not determine region for address 0x%08x (region is loaded in an additional REL) - Please pick the loaded region",
                            offset
                    ),
                    AskDialog.STRING,
                    ramRegions,
                    null
            );
            if (dialog.isCanceled()) return null;

            GameMemoryRegion region = dialog.getChoiceValue();
            return offset - region.ramAddr + region.ghidraAddr;
        }
    }

    public long addressToRam(Program program, Address addr) {
        ensureRegionMemoryList(program);

        long offset = addr.getOffset();
        GameMemoryRegion region = getRegionContainingAddress(program, offset);
        if (region != null) {
            return offset - region.ghidraAddr + region.ramAddr;
        }

        // Address not a "relocatable" region, treat it as RAM address
        return offset;
    }

    public Long addressToFile(Program program, Address addr) {
        ensureRegionMemoryList(program);

        long offset = addr.getOffset();
        GameMemoryRegion region = getRegionContainingAddress(program, offset);
        if (region != null && region.fileAddr != null) {
            return offset - region.ghidraAddr + region.fileAddr;
        }

        // Either there's no predefined memory region with an associated file offset,
        // or we're not in a predefined memory region at all
        return null;
    }

    public GameMemoryRegion getRegionContainingAddress(Program program, long addr) {
        ensureRegionMemoryList(program);

        for (GameMemoryRegion region : regions) {
            if (region.isAddressInRegion(addr)) {
                return region;
            }
        }

        // None found
        return null;
    }
}

//public class GameModuleIndexOld {
//    private static List<GameModule> modules = new ArrayList<>();
//    private static Program program; // Yeah we only cache one program..
//
//    //    private static final long RAM_OFFSET = 0x80000000L;
//    private static final long MAIN_LOOP_REL_OFFSET = 0x80270100L; // Always loaded
//    private static final long ADDITIONAL_REL_OFFSET = 0x808F3FE0L; // Loaded REL dependent on game mode
//    private static final long REL_HEADER_SIZE = 0xD8L;
//
//    /**
//     * @brief Convert a Ghidra address to an address in RAM
//     */
//    public static long addressToRam(Address addr, GameModule module) {
//        if (module.getBaseName().equals("main_loop_")) {
//            return addr.getOffset() - module.getStartAddress().getOffset() + MAIN_LOOP_REL_OFFSET + REL_HEADER_SIZE;
//        } else if (module.getBaseName().equals("MAIN_")) {
//            return addr.getOffset();
//        } else {
//            return addr.getOffset() - module.getStartAddress().getOffset() + ADDITIONAL_REL_OFFSET + REL_HEADER_SIZE;
//        }
//    }
//
//    /**
//     * Converts an address in GC RAM to a Ghidra address
//     *
//     * This func may pop open a dialog if it cannot determine what module the address is in!
//     */
//    public static Long ramToAddressUser(Program program, Address addr) {
//        long offset = addr.getOffset();
//        if (offset < MAIN_LOOP_REL_OFFSET) {
//            return offset;
//        } else if (offset < ADDITIONAL_REL_OFFSET) {
//            return offset -
//                    MAIN_LOOP_REL_OFFSET -
//                    REL_HEADER_SIZE +
//                    getModuleByBaseName(program, "main_loop_").getStartAddress().getOffset();
//        } else {
//            AskDialog<GameModule> dialog = new AskDialog<>(
//                    null,
//                    "Pick module",
//                    String.format(
//                            "Could not determine module for address 0x%08x (Module is loaded as an additional REL) - Please pick the loaded module",
//                            offset
//                            ),
//                    AskDialog.STRING,
//                    getModulesForProgram(program),
//                    null
//                    );
//            if (dialog.isCanceled()) return null;
//            GameModule module = dialog.getChoiceValue();
//
//            return offset -
//                    ADDITIONAL_REL_OFFSET -
//                    REL_HEADER_SIZE +
//                    module.getStartAddress().getOffset();
//        }
//    }
//
//    /**
//     * @brief Convert a Ghidra address to an address in a .rel/.dol file
//     */
//    public static long addressToFile(Address addr, GameModule module) {
//        if (module.getBaseName().equals("main_loop_")) {
//            return addr.getOffset() - module.getStartAddress().getOffset() + REL_HEADER_SIZE;
//        } else if (module.getBaseName().equals("MAIN_")) {
//            // return addr.getOffset() - 0x4220;
//            return addr.getOffset() - module.getStartAddress().getOffset() - 0x1120L;
//        } else {
//            return addr.getOffset() - module.getStartAddress().getOffset() + REL_HEADER_SIZE;
//        }
//    }
//
//    /**
//     * @brief Return the module that has the Ghidra address addr
//     */
//    public static GameModule getModuleContainingAddress(Program program, Address addr) {
//        for (GameModule module : getModulesForProgram(program)) {
//            if (module.isAddressInModule(addr)) {
//                return module;
//            }
//        }
//
//        // None found
//        return null;
//    }
//
//    /**
//     * @brief Return the module with the name name
//     */
//    public static GameModule getModuleByBaseName(Program program, String name) {
//        for (GameModule module : getModulesForProgram(program)) {
//            if (module.getBaseName().equals(name)) {
//                return module;
//            }
//        }
//
//        // None found
//        return null;
//    }
//
//    /**
//     * @brief Search through the program's memory map and build the modules list from it
//     */
//    public static void buildModuleList(Program program) {
//        GameModuleIndex.program = program;
//        modules.clear();
//
//        MemoryBlock prevBlock = null;
//        String prevModuleId = null;
//        for (MemoryBlock block : program.getMemory().getBlocks()) {
//            String[] parts = block.getName().split("\\.");
//            String moduleId;
//
//            if (!parts[0].startsWith("MAIN_")) {
//                if (parts.length < 3) {
//                    prevBlock = block;
//                    prevModuleId = null;
//                    continue;
//                }
//                if (!parts[0].equals("mkb2")) {
//                    prevBlock = block;
//                    prevModuleId = null;
//                    continue;
//                }
//
//                moduleId = parts[1]; // Will be something like "main_loop_"
//            } else {
//                moduleId = "MAIN_";
//            }
//
//            // Set the endAddr of the previous module
//            if (modules.size() > 0) {
//                GameModule prevModule = modules.get(modules.size() - 1);
//                prevModule.setEndAddress(prevBlock.getEnd());
//            }
//
//            if (moduleId.equals(prevModuleId)) {
//                prevBlock = block;
//                continue;
//            }
//
//            // New module
//            GameModule module = new GameModule(moduleId);
//            module.setStartAddress(block.getStart());
//            // endAddr will be set in a future loop iteration
//
//            modules.add(module);
//
//            prevBlock = block;
//            prevModuleId = moduleId;
//        }
//    }
//
//    public static List<GameModule> getModulesForProgram(Program program) {
//        if (GameModuleIndex.program == program) {
//            return modules;
//        } else {
//            buildModuleList(program);
//            return modules;
//        }
//    }
//}

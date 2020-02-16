package supermonkeyballtools;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.AskDialog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public class GameModuleIndex {
    private static List<GameModule> modules = new ArrayList<>();
    private static Program program; // Yeah we only cache one program..

    //    private static final long RAM_OFFSET = 0x80000000L;
    private static final long MAIN_LOOP_REL_OFFSET = 0x80270100L; // Always loaded
    private static final long ADDITIONAL_REL_OFFSET = 0x808F3FE0L; // Loaded REL dependent on game mode
    private static final long REL_HEADER_SIZE = 0xD8L;

    /**
     * @brief Convert a Ghidra address to an address in RAM
     */
    public static long addressToRam(Address addr, GameModule module) {
        if (module.getBaseName().equals("main_loop_")) {
            return addr.getOffset() - module.getStartAddress().getOffset() + MAIN_LOOP_REL_OFFSET + REL_HEADER_SIZE;
        } else if (module.getBaseName().equals("MAIN_")) {
            return addr.getOffset();
        } else {
            return addr.getOffset() - module.getStartAddress().getOffset() + ADDITIONAL_REL_OFFSET + REL_HEADER_SIZE;
        }
    }

    /**
     * Converts an address in GC RAM to a Ghidra address
     * 
     * This func may pop open a dialog if it cannot determine what module the address is in!
     */
    public static Long ramToAddressUser(Program program, Address addr) {
        long offset = addr.getOffset();
        if (offset < MAIN_LOOP_REL_OFFSET) {
            return offset;
        } else if (offset < ADDITIONAL_REL_OFFSET) {
            return offset -
                    MAIN_LOOP_REL_OFFSET -
                    REL_HEADER_SIZE +
                    getModuleByBaseName(program, "main_loop_").getStartAddress().getOffset();
        } else {
            AskDialog<GameModule> dialog = new AskDialog<>(
                    null,
                    "Pick module",
                    String.format(
                            "Could not determine module for address 0x%08x (Module is loaded as an additional REL) - Please pick the loaded module",
                            offset
                            ),
                    AskDialog.STRING,
                    getModulesForProgram(program),
                    null
                    );
            if (dialog.isCanceled()) return null;
            GameModule module = dialog.getChoiceValue();

            return offset -
                    ADDITIONAL_REL_OFFSET -
                    REL_HEADER_SIZE +
                    module.getStartAddress().getOffset();
        }
    }

    /**
     * @brief Convert a Ghidra address to an address in a .rel/.dol file
     */
    public static long addressToFile(Address addr, GameModule module) {
        if (module.getBaseName().equals("main_loop_")) {
            return addr.getOffset() - module.getStartAddress().getOffset() + REL_HEADER_SIZE;
        } else if (module.getBaseName().equals("MAIN_")) {
            // return addr.getOffset() - 0x4220;
            return addr.getOffset() - module.getStartAddress().getOffset() - 0x1120L;
        } else {
            return addr.getOffset() - module.getStartAddress().getOffset() + REL_HEADER_SIZE;
        }
    }

    /**
     * @brief Return the module that has the Ghidra address addr
     */
    public static GameModule getModuleContainingAddress(Program program, Address addr) {
        for (GameModule module : getModulesForProgram(program)) {
            if (module.isAddressInModule(addr)) {
                return module;
            }
        }

        // None found
        return null;
    }

    /**
     * @brief Return the module with the name name
     */
    public static GameModule getModuleByBaseName(Program program, String name) {
        for (GameModule module : getModulesForProgram(program)) {
            if (module.getBaseName().equals(name)) {
                return module;
            }
        }

        // None found
        return null;
    }

    /**
     * @brief Search through the program's memory map and build the modules list from it
     */
    public static void buildModuleList(Program program) {
        GameModuleIndex.program = program;
        modules.clear();

        MemoryBlock prevBlock = null;
        String prevModuleId = null;
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            String[] parts = block.getName().split("\\.");
            String moduleId;

            if (!parts[0].startsWith("MAIN_")) {
                if (parts.length < 3) {
                    prevBlock = block;
                    prevModuleId = null;
                    continue;
                }
                if (!parts[0].equals("mkb2")) {
                    prevBlock = block;
                    prevModuleId = null;
                    continue;
                }

                moduleId = parts[1]; // Will be something like "main_loop_"
            } else {
                moduleId = "MAIN_";
            }

            // Set the endAddr of the previous module
            if (modules.size() > 0) {
                GameModule prevModule = modules.get(modules.size() - 1);
                prevModule.setEndAddress(prevBlock.getEnd());
            }

            if (moduleId.equals(prevModuleId)) {
                prevBlock = block;
                continue;
            }

            // New module
            GameModule module = new GameModule(moduleId);
            module.setStartAddress(block.getStart());
            // endAddr will be set in a future loop iteration

            modules.add(module);

            prevBlock = block;
            prevModuleId = moduleId;
        }
    }

    public static List<GameModule> getModulesForProgram(Program program) {
        if (GameModuleIndex.program == program) {
            return modules;
        } else {
            buildModuleList(program);
            return modules;
        }
    }
}

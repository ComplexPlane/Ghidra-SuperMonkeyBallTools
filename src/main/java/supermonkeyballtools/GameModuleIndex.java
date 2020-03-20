package supermonkeyballtools;

import java.util.ArrayList;
import java.util.Arrays;
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
    private static final long REL_HEADER_SIZE = 0xD8L;

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

        // In the end, there isn't a lot of logic as to where exactly REL sections will be allocated in memory.
        // The start address of a REL can vary drastically as it's allocated on a heap, and
        // the sections within a REL can sometimes be loaded with extra padding in-between.
        // So, I figure it's better to explicitly initialize all regions for the most part here,
        // rather than try to precompute them // from the Ghidra sections and make corrections later.
        // Explicit over implicit.

        // test_mode.rel and option.rel are ignored for now, because they can be loaded at different locations depending on when they are invoked in the debug menu.
        // rel_sample.rel and exoption.rel are also ignored because they are seemingly never loaded anywhere.
        regions = new ArrayList<>(Arrays.asList(
                new GameMemoryRegion(RegionType.HARDWARE, "OS Globals", 0x3100L, 0x80000000L, 0x80000000L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "MAIN_.text0", 0x2520L, 0x80003100L, 0x80003100L, 0x00000100L),
                new GameMemoryRegion(RegionType.INITIALIZED, "MAIN_.data0", 0x740L, 0x80005620L, 0x80005620L, 0x0007af80L),
                new GameMemoryRegion(RegionType.INITIALIZED, "MAIN_.data1", 0xae0L, 0x80005d60L, 0x80005d60L, 0x0007b6c0L),
                new GameMemoryRegion(RegionType.INITIALIZED, "MAIN_.text1", 0x78960L, 0x80006840L, 0x80006840L, 0x00002620L),
                new GameMemoryRegion(RegionType.INITIALIZED, "MAIN_.data2", 0x20L, 0x8007f1a0L, 0x8007f1a0L, 0x0007c1a0L),
                new GameMemoryRegion(RegionType.INITIALIZED, "MAIN_.data3", 0x20L, 0x8007f1c0L, 0x8007f1c0L, 0x0007c1c0L),
                new GameMemoryRegion(RegionType.INITIALIZED, "MAIN_.data4", 0x2460L, 0x8007f1e0L, 0x8007f1e0L, 0x0007c1e0L),
                new GameMemoryRegion(RegionType.INITIALIZED, "MAIN_.data5", 0xc36e0L, 0x80081640L, 0x80081640L, 0x0007e640L),
                new GameMemoryRegion(RegionType.BSS, "MAIN_uninitialized0", 0x53b20L, 0x80144d20L, 0x80144d20L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "MAIN_.data6", 0x2e0L, 0x80198840L, 0x80198840L, 0x00141d20L),
                new GameMemoryRegion(RegionType.BSS, "MAIN_uninitialized1", 0x8e0L, 0x80198b20L, 0x80198b20L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "MAIN_.data7", 0xb60L, 0x80199400L, 0x80199400L, 0x00142000L),
                new GameMemoryRegion(RegionType.BSS, "MAIN_uninitialized2", 0x24L, 0x80199f60L, 0x80199f60L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.main_loop_.text0", 0x16d428L, 0x80199fa0L, 0x802701d8L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.main_loop_.data0", 0x4L, 0x803073c8L, 0x803dd600L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.main_loop_.data1", 0x4L, 0x803073ccL, 0x803dd604L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.main_loop_.data2", 0x66b48L, 0x803073d0L, 0x803dd608L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.main_loop_.data3", 0x806bcL, 0x8036df18L, 0x80444160L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.main_loop_.uninitialized0", 0xdda4cL, 0x803ee5e0L, 0x8054c8e0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.main_game_.text0", 0x209f4L, 0x804cc040L, 0x808f40b8L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.main_game_.data0", 0x4L, 0x804eca34L, 0x80914ab0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.main_game_.data1", 0x4L, 0x804eca38L, 0x80914ab4L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.main_game_.data2", 0xbc0L, 0x804eca3cL, 0x80914ab8L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.main_game_.data3", 0x5641cL, 0x804ed5fcL, 0x80915678L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.main_game_.uninitialized0", 0x65f0L, 0x80543a18L, 0x8097f4a0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.sel_ngc_.text0", 0x290f0L, 0x8054a020L, 0x808f40b8L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.sel_ngc_.data0", 0x4L, 0x80573110L, 0x8091d1a8L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.sel_ngc_.data1", 0x4L, 0x80573114L, 0x8091d1acL, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.sel_ngc_.data2", 0x1050L, 0x80573118L, 0x8091d1b0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.sel_ngc_.data3", 0x1188fL, 0x80574168L, 0x8091e200L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.sel_ngc_.uninitialized0", 0x8bd4L, 0x80585a00L, 0x80949ca0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.sel_stage_.text0", 0x1680L, 0x8058e5e0L, 0x808f40b0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.sel_stage_.data0", 0x4L, 0x8058fc60L, 0x808f5730L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.sel_stage_.data1", 0x4L, 0x8058fc64L, 0x808f5734L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.sel_stage_.data2", 0x48L, 0x8058fc68L, 0x808f5738L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.sel_stage_.data3", 0x609L, 0x8058fcb0L, 0x808f5780L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.sel_stage_.uninitialized0", 0x4L, 0x805902c0L, 0x808f6fa0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_mini_bowling_.text0", 0x1a350L, 0x805902e0L, 0x808f40b8L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_mini_bowling_.data0", 0x4L, 0x805aa630L, 0x8090e408L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_mini_bowling_.data1", 0x4L, 0x805aa634L, 0x8090e40cL, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_mini_bowling_.data2", 0x64a7L, 0x805aa638L, 0x8090e410L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_mini_bowling_.data3", 0x1858L, 0x805b0adfL, 0x809148b8L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.rel_mini_bowling_.uninitialized0", 0x1bb98L, 0x805b2338L, 0x8091e840L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_mini_billiards_.text0", 0x31870L, 0x805cdee0L, 0x808f40b8L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_mini_billiards_.data0", 0x4L, 0x805ff750L, 0x80925928L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_mini_billiards_.data1", 0x4L, 0x805ff754L, 0x8092592cL, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_mini_billiards_.data2", 0x4da4L, 0x805ff758L, 0x80925930L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_mini_billiards_.data3", 0x1f15L, 0x806044fcL, 0x8092a6d8L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.rel_mini_billiards_.uninitialized0", 0x109f4L, 0x80606418L, 0x80942dc0L, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_sample_.text0", 0x18cL, 0x80616e20L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_sample_.data0", 0x4L, 0x80616facL, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_sample_.data1", 0x4L, 0x80616fb0L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_sample_.data2", 0x234L, 0x80616fb4L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.BSS, "mkb2.rel_sample_.uninitialized0", 0x4L, 0x806171e8L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.test_mode_.text0", 0x202d4L, 0x80617200L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.test_mode_.data0", 0x4L, 0x806374d4L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.test_mode_.data1", 0x4L, 0x806374d8L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.test_mode_.data2", 0x608L, 0x806374dcL, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.test_mode_.data3", 0x112a2L, 0x80637ae4L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.BSS, "mkb2.test_mode_.uninitialized0", 0x5ae4L, 0x80648d88L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.option_.text0", 0xbd50L, 0x8064e880L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.option_.data0", 0x4L, 0x8065a5d0L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.option_.data1", 0x4L, 0x8065a5d4L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.option_.data2", 0x420L, 0x8065a5d8L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.option_.data3", 0x1dd0L, 0x8065a9f8L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.BSS, "mkb2.option_.uninitialized0", 0x6f4cL, 0x8065c7c8L, RAMADDR, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.race2_.text0", 0x21318L, 0x80663720L, 0x808f40b8L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.race2_.data0", 0x4L, 0x80684a38L, 0x809153d0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.race2_.data1", 0x4L, 0x80684a3cL, 0x809153d4L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.race2_.data2", 0x10e0L, 0x80684a40L, 0x809153d8L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.race2_.data3", 0x2df9L, 0x80685b20L, 0x809164b8L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.race2_.uninitialized0", 0x42c0L, 0x80688920L, 0x809234e0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.golf2_.text0", 0x38b04L, 0x8068cbe0L, 0x808f40b0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.golf2_.data0", 0x4L, 0x806c56e4L, 0x8092cbb8L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.golf2_.data1", 0x4L, 0x806c56e8L, 0x8092cbbcL, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.golf2_.data2", 0x11c4L, 0x806c56ecL, 0x8092cbc0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.golf2_.data3", 0x4f24L, 0x806c68b0L, 0x8092dd88L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.golf2_.uninitialized0", 0x2bd0L, 0x806cb7d8L, 0x80942ce0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.mini_fight2_.text0", 0x2df18L, 0x806ce3c0L, 0x808f40b0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.mini_fight2_.data0", 0x4L, 0x806fc2d8L, 0x80921fc8L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.mini_fight2_.data1", 0x4L, 0x806fc2dcL, 0x80921fccL, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.mini_fight2_.data2", 0xb58L, 0x806fc2e0L, 0x80921fd0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.mini_fight2_.data3", 0xa488L, 0x806fce38L, 0x80922b28L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.mini_fight2_.uninitialized0", 0x20088L, 0x807072c0L, 0x80939ac0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.pilot2_.text0", 0x13838L, 0x80727360L, 0x808f40b0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.pilot2_.data0", 0x4L, 0x8073ab98L, 0x809078e8L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.pilot2_.data1", 0x4L, 0x8073ab9cL, 0x809078ecL, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.pilot2_.data2", 0x92cL, 0x8073aba0L, 0x809078f0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.pilot2_.data3", 0x17b8L, 0x8073b4ccL, 0x80908220L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.pilot2_.uninitialized0", 0x228cL, 0x8073cc88L, 0x80910bc0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.boat_.text0", 0x24894L, 0x8073ef20L, 0x808f40b8L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.boat_.data0", 0x4L, 0x807637b4L, 0x80918950L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.boat_.data1", 0x4L, 0x807637b8L, 0x80918954L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.boat_.data2", 0x1240L, 0x807637bcL, 0x80918958L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.boat_.data3", 0x2246L, 0x807649fcL, 0x80919b98L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.boat_.uninitialized0", 0xc114L, 0x80766c48L, 0x80928980L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.shooting_.text0", 0x400f8L, 0x80772d60L, 0x808f40b0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.shooting_.data0", 0x4L, 0x807b2e58L, 0x809341a8L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.shooting_.data1", 0x4L, 0x807b2e5cL, 0x809341acL, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.shooting_.data2", 0x2014L, 0x807b2e60L, 0x809341b0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.shooting_.data3", 0x51b54L, 0x807b4e74L, 0x809361c8L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.shooting_.uninitialized0", 0x2c9bcL, 0x808069c8L, 0x809a5740L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_mini_futsal_.text0", 0x2bf80L, 0x808333a0L, 0x808f40b0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_mini_futsal_.data0", 0x4L, 0x8085f320L, 0x80920030L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_mini_futsal_.data1", 0x4L, 0x8085f324L, 0x80920034L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_mini_futsal_.data2", 0x1408L, 0x8085f328L, 0x80920038L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.rel_mini_futsal_.data3", 0x61cL, 0x80860730L, 0x80921440L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.rel_mini_futsal_.uninitialized0", 0x6433cL, 0x80860d50L, 0x809369a0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.dogfight_.text0", 0x16f90L, 0x808c50a0L, 0x808f40b0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.dogfight_.data0", 0x4L, 0x808dc030L, 0x8090b040L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.dogfight_.data1", 0x4L, 0x808dc034L, 0x8090b044L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.dogfight_.data2", 0xbbcL, 0x808dc038L, 0x8090b048L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.dogfight_.data3", 0x1728L, 0x808dcbf4L, 0x8090bc08L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.dogfight_.uninitialized0", 0x12b34L, 0x808de320L, 0x809150c0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.baseball_.text0", 0x27b44L, 0x808f0e60L, 0x808e8390L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.baseball_.data0", 0x4L, 0x809189a4L, 0x8090fee0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.baseball_.data1", 0x4L, 0x809189a8L, 0x8090fee4L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.baseball_.data2", 0x4160L, 0x809189acL, 0x8090fee8L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.baseball_.data3", 0x82f4cL, 0x8091cb0cL, 0x80914048L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.baseball_.uninitialized0", 0x1a3e8L, 0x8099fa58L, 0x809b06a0L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.tennis_.text0", 0x28dbcL, 0x809b9e40L, 0x808e8398L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.tennis_.data0", 0x4L, 0x809e2bfcL, 0x80911158L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.tennis_.data1", 0x4L, 0x809e2c00L, 0x8091115cL, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.tennis_.data2", 0x1375L, 0x809e2c04L, 0x80911160L, null),
                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.tennis_.data3", 0x952fL, 0x809e3f79L, 0x809124d8L, null),
                new GameMemoryRegion(RegionType.BSS, "mkb2.tennis_.uninitialized0", 0x1118L, 0x809ed4a8L, 0x8092caa0L, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.exoption_.text0", 0x2ec4L, 0x809ee5c0L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.exoption_.data0", 0x4L, 0x809f1484L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.exoption_.data1", 0x4L, 0x809f1488L, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.exoption_.data2", 0x100L, 0x809f148cL, RAMADDR, null),
//                new GameMemoryRegion(RegionType.INITIALIZED, "mkb2.exoption_.data3", 0x51eL, 0x809f158cL, RAMADDR, null),
//                new GameMemoryRegion(RegionType.BSS, "mkb2.exoption_.uninitialized0", 0x80L, 0x809f1ab0L, RAMADDR, null),
                new GameMemoryRegion(RegionType.HARDWARE, "CP", 0x80L, 0xcc000000L, 0xcc000000L, null),
                new GameMemoryRegion(RegionType.HARDWARE, "PE", 0x100L, 0xcc001000L, 0xcc001000L, null),
                new GameMemoryRegion(RegionType.HARDWARE, "VI", 0x100L, 0xcc002000L, 0xcc002000L, null),
                new GameMemoryRegion(RegionType.HARDWARE, "PI", 0x100L, 0xcc003000L, 0xcc003000L, null),
                new GameMemoryRegion(RegionType.HARDWARE, "MI", 0x80L, 0xcc004000L, 0xcc004000L, null),
                new GameMemoryRegion(RegionType.HARDWARE, "DSP", 0x200L, 0xcc005000L, 0xcc005000L, null),
                new GameMemoryRegion(RegionType.HARDWARE, "DI", 0x40L, 0xcc006000L, 0xcc006000L, null),
                new GameMemoryRegion(RegionType.HARDWARE, "SI", 0x100L, 0xcc006400L, 0xcc006400L, null),
                new GameMemoryRegion(RegionType.HARDWARE, "EXI", 0x40L, 0xcc006800L, 0xcc006800L, null),
                new GameMemoryRegion(RegionType.HARDWARE, "AI", 0x40L, 0xcc006c00L, 0xcc006c00L, null),
                new GameMemoryRegion(RegionType.HARDWARE, "GXFIFO", 0x8L, 0xcc008000L, 0xcc008000L, null)
        ));

        // Compute the file addresses based on the RAM addresses for all REL sections (DOL was manually filled in)

        String lastModuleName = null;
        long lastModuleRamAddr = 0;

        for (GameMemoryRegion region : regions) {
            if (region.name.startsWith("mkb2") && region.regionType == RegionType.INITIALIZED) {
                String moduleName = region.getModuleName();
                if (!moduleName.equals(lastModuleName)) {
                    lastModuleName = moduleName;
                    lastModuleRamAddr = region.ramAddr;
                }

                region.fileAddr = region.ramAddr - lastModuleRamAddr + REL_HEADER_SIZE;
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

package supermonkeyballtools;

import java.awt.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.core.compositeeditor.DuplicateMultipleAction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GoToService;
import ghidra.app.util.dialog.AskAddrDialog;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class SmbAddressConvertComponent extends ComponentProvider {
    private JPanel panel;
    private JTextArea textArea;

    private ProgramLocation cursorLoc;
    private GameModuleIndex regionIndex;
    private DmeExport dmeExport;
    private CppExport cppExport;

    public SmbAddressConvertComponent(Plugin plugin, String owner, GameModuleIndex regionIndex) {
        super(plugin.getTool(), "SMB: Convert Address", owner);
        this.regionIndex = regionIndex;

        buildPanel();
        createActions();
    }

    private void buildPanel() {
        panel = new JPanel(new BorderLayout());
        textArea = new JTextArea();
        Font font = new Font(Font.MONOSPACED, Font.PLAIN, 12);
        font = SystemUtilities.adjustForFontSizeOverride(font);
        textArea.setFont(font);
        textArea.setEditable(false);
        updateLocations();
        panel.add(new JScrollPane(textArea));
        setVisible(true);
    }

    private void createActions() {
        // Jump to GC RAM address
        DockingAction jumpToGcRamAction = new DockingAction("Jump to GC RAM address", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                AskAddrDialog dialog = new AskAddrDialog(
                        "Jump to GameCube RAM address",
                        "Jump to GameCube RAM address",
                        cursorLoc.getProgram().getAddressFactory(),
                        cursorLoc.getAddress()
                );
                if (dialog.isCanceled()) return;
                Address addr = dialog.getValueAsAddress();
                Long ghidraOffset = regionIndex.ramToAddressUser(cursorLoc.getProgram(), addr);
                if (ghidraOffset == null) return;
                Address ghidraAddr = cursorLoc.getAddress().getAddressSpace().getAddress(ghidraOffset);

                GoToService service = dockingTool.getService(GoToService.class);
                if (service != null) {
                    service.goTo(ghidraAddr);
                }
            }
        };
        jumpToGcRamAction.setToolBarData(new ToolBarData(SmbIcons.JUMP_TO_ICON, null));
        jumpToGcRamAction.setEnabled(true);
        jumpToGcRamAction.markHelpUnnecessary();
        dockingTool.addLocalAction(this, jumpToGcRamAction);

        // Export cube_code symbol map
        DockingAction exportCubeCodeMapAction = new DockingAction("Export cube_code symbol map", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                saveFile("cube_code symbol map", "smb2_symbol_map.json", generateCubeCodeSymbolMap());
            }
        };
        exportCubeCodeMapAction.setToolBarData(new ToolBarData(ProgramContentHandler.PROGRAM_ICON, null));
        exportCubeCodeMapAction.setEnabled(true);
        exportCubeCodeMapAction.markHelpUnnecessary();
        dockingTool.addLocalAction(this, exportCubeCodeMapAction);

        // Export ApeSphere-style symbol map
        DockingAction exportApeSphereMapAction = new DockingAction("Export ApeSphere symbol map", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                saveFile("ApeSphere symbol map", "mkb2.us.lst", generateApeSphereSymbolMap());
            }
        };
        exportApeSphereMapAction.setToolBarData(new ToolBarData(ProgramContentHandler.PROGRAM_ICON, null));
        exportApeSphereMapAction.setEnabled(true);
        exportApeSphereMapAction.markHelpUnnecessary();
        dockingTool.addLocalAction(this, exportApeSphereMapAction);

        // Export DME watchlist
        DockingAction exportDmeAction = new DockingAction("Export Dolphin Memory Engine watch list", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                saveFile("DME watch list", "smb2_watchlist.dmw",
                        dmeExport.genDmeWatchList());
            }
        };
        exportDmeAction.setToolBarData(new ToolBarData(ProgramContentHandler.PROGRAM_ICON, null));
        exportDmeAction.setEnabled(true);
        exportDmeAction.markHelpUnnecessary();
        dockingTool.addLocalAction(this, exportDmeAction);

        // Export C++ header, intended for ApeSphere
        // TODO do this at the same time as exporting ApeSphere symbol list
        DockingAction exportCppHeaderAction = new DockingAction("Export C++ header", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                saveFile("C++ header", "mkb2_ghidra.h",
                        cppExport.genCppHeader());
            }
        };
        exportCppHeaderAction.setToolBarData(new ToolBarData(DebuggerResources.ICON_CONSOLE, null));
        exportCppHeaderAction.setEnabled(true);
        exportCppHeaderAction.markHelpUnnecessary();
        dockingTool.addLocalAction(this, exportCppHeaderAction);
    }

    private void updateLocations() {
        if (cursorLoc == null) return;

        Program program = cursorLoc.getProgram();
        Address ghidraAddr = cursorLoc.getAddress();
        GameMemoryRegion region = regionIndex.getRegionContainingAddress(cursorLoc.getProgram(), ghidraAddr.getOffset());

        String fileLocStr;
        Long fileLoc = regionIndex.addressToFile(cursorLoc.getProgram(), ghidraAddr);
        if (fileLoc == null) {
            fileLocStr = "NONE";
        } else {
            fileLocStr = String.format("0x%08x", fileLoc);
        }

        // Get whether the block is read-write or read-only
        MemoryBlock block = program.getMemory().getBlock(ghidraAddr);
        String writeableStatus = block.isWrite() ? "read-write" : "read-only";

        if (region != null) {
            textArea.setText(
                    String.format(
                            "Region               : %s (%s)\n" +
                                    "Ghidra location      : 0x%08x\n" +
                                    "GC RAM location      : 0x%08x\n" +
                                    "REL/DOL file location: %s",
                            region.name,
                            writeableStatus,
                            ghidraAddr.getOffset(),
                            regionIndex.addressToRam(cursorLoc.getProgram(), ghidraAddr),
                            fileLocStr
                    )
            );
        } else {
            textArea.setText("Cursor not in module");
        }
    }

    private String generateCubeCodeSymbolMap() {
        String json = "{\n" +
                "  \"symbols\": {\n";

        Program program = cursorLoc.getProgram();
        List<String> symbolStrs = new ArrayList<>();
        for (Symbol s : program.getSymbolTable().getSymbolIterator()) {
            GameMemoryRegion module = regionIndex.getRegionContainingAddress(cursorLoc.getProgram(), s.getAddress().getOffset());
            if (module != null && (module.regionType == RegionType.HARDWARE || module.name.startsWith("MAIN_"))) {
                symbolStrs.add(String.format("    \"%s\": { \"module_id\": 0, \"section_id\": 0, \"offset\": %d }", s.getName(), s.getAddress().getOffset()));
            }
        }

        return json +
                String.join(",\n", symbolStrs) + "\n" +
                "  }\n" +
                "}\n";
    }

    private String generateApeSphereSymbolMap() {
        Program program = cursorLoc.getProgram();
        List<String> symbolStrs = new ArrayList<>();
        for (Symbol s : program.getSymbolTable().getSymbolIterator()) {
            symbolStrs.add(String.format("%08X:%s", regionIndex.addressToRam(program, s.getAddress()), s.getName()));
        }
        return String.join("\n", symbolStrs);
    }

    private void saveFile(String type, String defaultFilename, String contents) {
        ProgramUserData pud = cursorLoc.getProgram().getProgramUserData();
        int tid = pud.startTransaction();
        try {
            // Get previous filepath used if it exists, otherwise use default filename
            StringPropertyMap smap = pud.getStringProperty("SMB Export Paths", type, true);
            String exportPath = smap.getString(cursorLoc.getProgram().getMinAddress());
            if (exportPath == null) {
                exportPath = defaultFilename;
            }

            JFileChooser dialog = new JFileChooser();
            dialog.setSelectedFile(new File(exportPath));
            dialog.setDialogTitle("Specify where to save " + type);

            int result = dialog.showSaveDialog(null);
            if (result == JFileChooser.APPROVE_OPTION) {
                // Write chosen filepath to datastore
                String newPath = dialog.getSelectedFile().getAbsolutePath();
                smap.add(cursorLoc.getProgram().getMinAddress(), newPath);

                try (PrintWriter writer = new PrintWriter(dialog.getSelectedFile())) {
                    writer.print(contents);
                } catch (FileNotFoundException e) {
                    Msg.error(getClass(), e);
                }

                Msg.info(getClass(), "Exported " + type + " for program " + cursorLoc.getProgram().getName());
            }
        } finally {
            pud.endTransaction(tid);
        }
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    public void locationChanged(ProgramLocation loc) {
        if (loc == null) return;

        cursorLoc = loc;

        // Can only initialize exporter once we know the Program in question
        if (dmeExport == null) {
            dmeExport = new DmeExport(cursorLoc.getProgram(), regionIndex);
            cppExport = new CppExport(cursorLoc.getProgram());
        }

        updateLocations();
    }
}

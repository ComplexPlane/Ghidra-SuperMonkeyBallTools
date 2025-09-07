package supermonkeyballtools;

import java.awt.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import com.google.gson.Gson;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.script.AskDialog;
import ghidra.app.services.GoToService;
import ghidra.app.util.dialog.AskAddrDialog;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import supermonkeyballtools.addr.DeltaAddr;
import supermonkeyballtools.addr.GhidraAddr;
import supermonkeyballtools.addr.RamAddr;

public class SmbAddressConvertComponent extends ComponentProvider {
    private JPanel panel;
    private JTextArea textArea;

    private ProgramLocation cursorLoc;
    private RegionIndex regionIndex;
    private BetterHeaderExport betterHeaderExport;

    public SmbAddressConvertComponent(Plugin plugin, String owner) {
        super(plugin.getTool(), "SMB: Convert Address", owner);
        this.regionIndex = new RegionIndex();

        buildPanel();
        createActions();
    }

    public RegionIndex getRegionIndex() {
        return this.regionIndex;
    }

    private void buildPanel() {
        panel = new JPanel(new BorderLayout());
        textArea = new JTextArea();
        Font font = new Font(Font.MONOSPACED, Font.PLAIN, 12);
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
                        cursorLoc.getProgram(),
                        cursorLoc.getAddress()
                );
                if (dialog.isCanceled()) return;
                RamAddr ramAddr = new RamAddr(dialog.getValueAsAddress().getOffset());
                GhidraAddr ghidraAddr = regionIndex.ramToGhidraAddr(ramAddr);
                if (ghidraAddr == null) return;
                Address address = ghidraAddr.toAddress(cursorLoc.getAddress().getAddressSpace());

                GoToService service = dockingTool.getService(GoToService.class);
                if (service != null) {
                    service.goTo(address);
                }
            }
        };
        jumpToGcRamAction.setToolBarData(new ToolBarData(SmbIcons.JUMP_TO_ICON, null));
        jumpToGcRamAction.setEnabled(true);
        jumpToGcRamAction.markHelpUnnecessary();
        dockingTool.addLocalAction(this, jumpToGcRamAction);

        // Import module RAM locations
        SmbAddressConvertComponent thisObj = this;
        DockingAction importModuleRamLocationsAction = new DockingAction("Import module RAM locations", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                String contents = loadFile("Module RAM locations JSON file", "locations.json");
                thisObj.regionIndex = new RegionIndex(contents);
                thisObj.updateLocations();
            }
        };
        importModuleRamLocationsAction.setToolBarData(new ToolBarData(DebuggerResources.ICON_ADD, null));
        importModuleRamLocationsAction.setEnabled(true);
        importModuleRamLocationsAction.markHelpUnnecessary();
        dockingTool.addLocalAction(this, importModuleRamLocationsAction);

        // Export C/C++ header, non merged heaps
        DockingAction exportApeSphereStuffAction = new DockingAction("Export Practice/Workshop Mod symbol map and C/C++ header", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                saveApeSphereStuff(false);
            }
        };
        exportApeSphereStuffAction.setToolBarData(new ToolBarData(DebuggerResources.ICON_CONSOLE, null));
        exportApeSphereStuffAction.setEnabled(true);
        exportApeSphereStuffAction.markHelpUnnecessary();
        dockingTool.addLocalAction(this, exportApeSphereStuffAction);
        
        // Export C/C++ header, merged heaps
        DockingAction exportApeSphereMergeHeapsStuffAction = new DockingAction("Export Practice/Workshop Mod symbol map and C/C++ header (merge-heaps)", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                saveApeSphereStuff(true);
            }
        };
        exportApeSphereMergeHeapsStuffAction.setToolBarData(new ToolBarData(DebuggerResources.ICON_PROVIDER_PCODE, null));
        exportApeSphereMergeHeapsStuffAction.setEnabled(true);
        exportApeSphereMergeHeapsStuffAction.markHelpUnnecessary();
        dockingTool.addLocalAction(this, exportApeSphereMergeHeapsStuffAction);
    }

    private void updateLocations() {
        if (cursorLoc == null) return;

        GhidraAddr ghidraAddr = new GhidraAddr(cursorLoc.getAddress().getOffset());
        Region region = regionIndex.getRegionContainingGhidraAddr(ghidraAddr);
        RamAddr ramAddr = regionIndex.ghidraAddrToRam(ghidraAddr);

        // Get whether the block is read-write or read-only
        MemoryBlock block = cursorLoc.getProgram().getMemory().getBlock(cursorLoc.getAddress());
        String writeableStatus = block.isWrite() ? "read-write" : "read-only";

        if (region != null) {
            String moduleId = region.relSection != null 
                ? String.valueOf(region.relSection.moduleId) 
                : "?";
            String regionIdx = region.relSection != null 
                ? String.valueOf(region.relSection.sectionIdx) 
                : "?";
            String ghidraLocation = ghidraAddr != null ? ghidraAddr.toString() : "?";
            String ramLocation = ramAddr != null ? ramAddr.toString() : "?";
            textArea.setText(
                    String.format("Region          : %s (%s, %s) (%s)\n" +
                                  "Ghidra location : %s\n" +
                                  "GC RAM location : %s",
                            region.name, moduleId, regionIdx, writeableStatus,
                            ghidraLocation,
                            ramLocation
                    )
            );
        } else {
            textArea.setText("Cursor not in module");
        }
    }

    private String generateApeSphereSymbolMap(boolean mergeHeaps) {
        Program program = cursorLoc.getProgram();
        List<String> symbolStrs = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getSymbolIterator()) {
            GhidraAddr ghidraAddr = new GhidraAddr(symbol.getAddress().getOffset());
            Region region = regionIndex.getRegionContainingGhidraAddr(ghidraAddr);
            if (region != null) {
                if (region.relSection != null && mergeHeaps) {
                    DeltaAddr delta = ghidraAddr.sub(region.ghidraAddr);
                    // Export symbol as section offset
                    symbolStrs.add(String.format("%X,%X,%s:%s",
                            region.relSection.moduleId, region.relSection.sectionIdx, delta.toString(), symbol.getName()));
                } else {
                    // Export symbol as global address (DOL, 0xE0000000 range, non merge-heaps)
                    RamAddr ramAddr = regionIndex.ghidraAddrToRam(ghidraAddr);
                    symbolStrs.add(String.format("%s:%s", ramAddr.toString(), symbol.getName()));
                }
            }
        }
        return String.join("\n", symbolStrs);
    }

    private String getCachedPath(String pathType, String defaultPath) {
        ProgramUserData pud = cursorLoc.getProgram().getProgramUserData();
        int tid = pud.startTransaction();
        try {
            StringPropertyMap smap = pud.getStringProperty("SMB Export Paths", pathType, true);
            String exportPath = smap.getString(cursorLoc.getProgram().getMinAddress());
            if (exportPath == null) {
                exportPath = defaultPath;
            }
            return exportPath;
        } finally {
            pud.endTransaction(tid);
        }
    }

    private void setCachedPath(String pathType, String path) {
        ProgramUserData pud = cursorLoc.getProgram().getProgramUserData();
        int tid = pud.startTransaction();
        try {
            StringPropertyMap smap = pud.getStringProperty("SMB Export Paths", pathType, true);
            smap.add(cursorLoc.getProgram().getMinAddress(), path);
        } finally {
            pud.endTransaction(tid);
        }
    }

    private String loadFile(String type, String defaultFilename) {
        String importPath = getCachedPath(type, defaultFilename);

        JFileChooser dialog = new JFileChooser();
        dialog.setSelectedFile(new File(importPath)); 
        dialog.setDialogTitle("Select " + type + " to load");

        int result = dialog.showOpenDialog(null);
        if (result == JFileChooser.APPROVE_OPTION) {
            // Cache the chosen filepath
            String newPath = dialog.getSelectedFile().getAbsolutePath();
            setCachedPath(type, newPath);

            try {
                return Files.readString(dialog.getSelectedFile().toPath());
            } catch (IOException e) {
                Msg.error(getClass(), e);
                throw new Error(e);
            }
        }
        return null;
    }

    private void writeDirFile(File dir, String fileName, String contents) {
        String filePath = dir.toPath().resolve(fileName).toString();
        File file = new File(filePath);
        try {
            file.createNewFile(); // Creates if doesn't exist already
            try (PrintWriter writer = new PrintWriter(file)) {
                writer.print(contents);
            }
        } catch (Exception e) {
            Msg.error(getClass(), e);
        }
    }

    private void saveApeSphereStuff(boolean mergeHeaps) {
        // Generate stuff first so file dialog popping up indicates they're done exporting
        String symbolMap = generateApeSphereSymbolMap(mergeHeaps);
        String header = betterHeaderExport.genCppHeader();

        JFileChooser dialog = new JFileChooser();
        dialog.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        String pathType = "ApeSphere Stuff";
        String cachedPath = getCachedPath(pathType, null);
        if (cachedPath != null) {
            dialog.setSelectedFile(new File(cachedPath));
        }
        dialog.setDialogTitle("Specify Practice/Workshop mod /rel/include dir, to save symbol map and C/C++ header");

        int result = dialog.showSaveDialog(null);
        if (result == JFileChooser.APPROVE_OPTION) {
            File saveDir = dialog.getSelectedFile();
            setCachedPath(pathType, saveDir.getAbsolutePath());
            writeDirFile(saveDir, "mkb2.us.lst", symbolMap);
            writeDirFile(saveDir, "mkb2_ghidra.h", header);
        }
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    public void locationChanged(ProgramLocation loc) {
        if (loc == null) return;
        cursorLoc = loc;
        updateLocations();
    }
}

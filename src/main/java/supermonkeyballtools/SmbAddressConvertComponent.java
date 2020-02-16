package supermonkeyballtools;

import java.awt.BorderLayout;
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
import ghidra.app.services.GoToService;
import ghidra.app.util.dialog.AskAddrDialog;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import resources.Icons;

public class SmbAddressConvertComponent extends ComponentProvider {
    private JPanel panel;
    private JTextArea textArea;

    private ProgramLocation cursorLoc;
    
    private File lastSymbolExportFile = new File("smb2_symbol_map.json");

    public SmbAddressConvertComponent(Plugin plugin, String owner) {
        super(plugin.getTool(), "SMB: Convert Address", owner);
        
        buildPanel();
        createActions();
    }

    private void buildPanel() {
        panel = new JPanel(new BorderLayout());
        textArea = new JTextArea();
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
                Long ghidraOffset = GameModuleIndex.ramToAddressUser(cursorLoc.getProgram(), addr);
                if (ghidraOffset == null) return;
                Address ghidraAddr = cursorLoc.getAddress().getAddressSpace().getAddress(ghidraOffset);

                GoToService service = ((PluginTool) dockingTool).getService(GoToService.class);
                if (service != null) {
                    service.goTo(ghidraAddr);
                }
            }
        };
        jumpToGcRamAction.setToolBarData(new ToolBarData(SmbIcons.JUMP_TO_ICON, null));
        jumpToGcRamAction.setEnabled(true);
        jumpToGcRamAction.markHelpUnnecessary();
        dockingTool.addLocalAction(this, jumpToGcRamAction);

        // Rebuild module list
        DockingAction rebuildAction = new DockingAction("Rebuild module list", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                GameModuleIndex.buildModuleList(cursorLoc.getProgram());
                Msg.info(getClass(), "Module list rebuilt for program " + cursorLoc.getProgram().getName());
                updateLocations();
            }
        };
        rebuildAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
        rebuildAction.setEnabled(true);
        rebuildAction.markHelpUnnecessary();
        dockingTool.addLocalAction(this, rebuildAction);

        // Export cube_code symbol map
        DockingAction exportMapAction = new DockingAction("Export cube_code symbol map", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                JFileChooser dialog = new JFileChooser();
                dialog.setSelectedFile(lastSymbolExportFile);
                dialog.setDialogTitle("Specify where to save cube_code symbol map");
                int result = dialog.showSaveDialog(null);
                
                if (result == JFileChooser.APPROVE_OPTION) {
                    File fileToSave = dialog.getSelectedFile();
                    lastSymbolExportFile = fileToSave;
                    
                    String json = generateSymbolMap();
                    
                    try (PrintWriter writer = new PrintWriter(fileToSave)) {
                        writer.print(json);
                    } catch (FileNotFoundException e) {
                        Msg.error(getClass(), e);
                    }
                    
                    Msg.info(getClass(), "Exported cube_code symbol map for program " + cursorLoc.getProgram().getName());
                }
            }
        };
        exportMapAction.setToolBarData(new ToolBarData(ProgramContentHandler.PROGRAM_ICON, null));
        exportMapAction.setEnabled(true);
        exportMapAction.markHelpUnnecessary();
        dockingTool.addLocalAction(this, exportMapAction);
    }

    private void updateLocations() {
        if (cursorLoc == null) return;

        Program program = cursorLoc.getProgram();
        Address ghidraAddr = cursorLoc.getAddress();
        GameModule module = GameModuleIndex.getModuleContainingAddress(program, ghidraAddr);

        if (module != null) {
            textArea.setText(
                String.format(
                    "Module               : %s\n" +
                    "Ghidra location      : 0x%08x\n" +
                    "GC RAM location      : 0x%08x\n" +
                    "REL/DOL file location: 0x%08x",
                    module.getBaseName(),
                    ghidraAddr.getOffset(),
                    GameModuleIndex.addressToRam(ghidraAddr, module),
                    GameModuleIndex.addressToFile(ghidraAddr, module)
                    )
                );
        } else {
            textArea.setText("Cursor not in module");
        }
    }
    
    private String generateSymbolMap() {
        String json = "{\n" +
                "  \"symbols\": {\n";

        Program program = cursorLoc.getProgram();
        List<String> symbol_strs = new ArrayList<>();
        for (Symbol s : program.getSymbolTable().getSymbolIterator()) {
            GameModule module = GameModuleIndex.getModuleContainingAddress(program, s.getAddress());
            if (module == null || module.getBaseName() == "MAIN_") {
                symbol_strs.add(String.format("    \"%s\": { \"module_id\": 0, \"section_id\": 0, \"offset\": %d }", s.getName(), s.getAddress().getOffset()));
            }
        }
        
        return json +
                String.join(",\n", symbol_strs) + "\n" +
                "  }\n" +
                "}\n";
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
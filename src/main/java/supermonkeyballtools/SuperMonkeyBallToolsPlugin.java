/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package supermonkeyballtools;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.util.dialog.AskAddrDialog;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;

//@formatter:off
@PluginInfo(
        status = PluginStatus.STABLE,
        packageName = "Common",
        category = PluginCategoryNames.COMMON,
        shortDescription = "Tools to help with reversing Super Monkey Ball 2",
        description = "Tools to help with reversing Super Monkey Ball 2"
        )
//@formatter:on
public class SuperMonkeyBallToolsPlugin extends ProgramPlugin {
    SmbAddressConvertComponent addressConvertComp;
    GoToService goToService;
    private GameModuleIndex regionIndex;
    private Address lastGcRamAddress;

    /**
     * Plugin constructor.
     * 
     * @param tool The plugin tool that this plugin is added to.
     */
    public SuperMonkeyBallToolsPlugin(PluginTool tool) {
        super(tool, true, true);
        regionIndex = new GameModuleIndex();

        String pluginName = getName();
        addressConvertComp = new SmbAddressConvertComponent(this, pluginName, regionIndex);

        // String topicName = this.getClass().getPackage().getName();
        // String anchorName = "HelpAnchor";
        // provider.setHelpLocation(new HelpLocation(topicName, anchorName));
        
		DockingAction goToRamAction = new NavigatableContextAction("SMB: Go To GameCube RAM Address", getName()) {
			@Override
			public void actionPerformed(NavigatableActionContext context) {
			    if (lastGcRamAddress == null) {
			        // Should be 0x80000000 both in Ghidra and in gamecube RAM
                    lastGcRamAddress = currentLocation.getProgram().getMinAddress();
                }

                AskAddrDialog dialog = new AskAddrDialog(
                        "Jump to GameCube RAM address",
                        "Jump to GameCube RAM address",
                        currentLocation.getProgram().getAddressFactory(),
                        lastGcRamAddress
                        );
                if (dialog.isCanceled()) return;
                lastGcRamAddress = dialog.getValueAsAddress();
                Long ghidraOffset = regionIndex.ramToAddressUser(currentProgram, lastGcRamAddress);
                if (ghidraOffset == null) return;
                Address ghidraAddr = currentLocation.getAddress().getAddressSpace().getAddress(ghidraOffset);

                GoToService service = tool.getService(GoToService.class);
                if (service != null) {
                    service.goTo(ghidraAddr);
                }
			}
		};
		// action.setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, action.getName()));
		goToRamAction.setMenuBarData(
            new MenuData(
                new String[] {ToolConstants.MENU_NAVIGATION, "SMB: Go To GameCube RAM Address..." },
                null,
                "SMBGoToGamecubeRamAddress",
                MenuData.NO_MNEMONIC,
                null
                )
            );

		goToRamAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_G, InputEvent.SHIFT_DOWN_MASK));

		tool.addAction(goToRamAction);
    }

    @Override
    public void init() {
        super.init();
    }

    @Override
    protected void locationChanged(ProgramLocation loc) {
        addressConvertComp.locationChanged(loc);
    }
}

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
package supermonkeyballtools.ui;

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
import supermonkeyballtools.addr.GhidraAddr;
import supermonkeyballtools.addr.RamAddr;

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

    /**
     * Plugin constructor.
     * 
     * @param tool The plugin tool that this plugin is added to.
     */
    public SuperMonkeyBallToolsPlugin(PluginTool tool) {
        super(tool);

        String pluginName = getName();
        addressConvertComp = new SmbAddressConvertComponent(this, pluginName);

        // String topicName = this.getClass().getPackage().getName();
        // String anchorName = "HelpAnchor";
        // provider.setHelpLocation(new HelpLocation(topicName, anchorName));
        
		DockingAction goToRamAction = new NavigatableContextAction("SMB: Go To GameCube RAM Address", getName()) {
            private Address lastRamAddress;

			@Override
			public void actionPerformed(NavigatableActionContext context) {
			    if (this.lastRamAddress == null) {
			        // Should be 0x80000000 both in Ghidra and in gamecube RAM
                    this.lastRamAddress = currentLocation.getProgram().getMinAddress();
                }

                AskAddrDialog dialog = new AskAddrDialog(
                        "Jump to GameCube RAM address",
                        "Jump to GameCube RAM address",
                        currentLocation.getProgram(),
                        this.lastRamAddress
                        );
                if (dialog.isCanceled()) return;
                this.lastRamAddress = dialog.getValueAsAddress();

                RamAddr ramAddr = new RamAddr(this.lastRamAddress.getOffset());
                GhidraAddr ghidraAddr = addressConvertComp.getRegionIndex().ramToGhidraAddr(ramAddr);
                if (ghidraAddr == null) return;
                Address address = ghidraAddr.toAddress(currentLocation.getAddress().getAddressSpace());

                GoToService service = tool.getService(GoToService.class);
                if (service != null) {
                    service.goTo(address);
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

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

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
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

    /**
     * Plugin constructor.
     * 
     * @param tool The plugin tool that this plugin is added to.
     */
    public SuperMonkeyBallToolsPlugin(PluginTool tool) {
        super(tool, true, true);

        String pluginName = getName();
        addressConvertComp = new SmbAddressConvertComponent(this, pluginName);

        // String topicName = this.getClass().getPackage().getName();
        // String anchorName = "HelpAnchor";
        // provider.setHelpLocation(new HelpLocation(topicName, anchorName));
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

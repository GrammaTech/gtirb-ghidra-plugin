/*
 *  Copyright (C) 2020 GrammaTech, Inc.
 *
 *  This code is licensed under the MIT license. See the LICENSE file in the
 *  project root for license terms.
 *
 *  This project is sponsored by the Office of Naval Research, One Liberty
 *  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
 *  N68335-17-C-0700.  The content of the information does not necessarily
 *  reflect the position or policy of the Government and no official
 *  endorsement should be inferred.
 *
 */
package com.grammatech.gtirb_ghidra_plugin;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import java.awt.BorderLayout;
import javax.swing.*;
import resources.Icons;

/** TODO: Provide class-level documentation that describes what this plugin does. */
// @formatter:off
@PluginInfo(
        status = PluginStatus.STABLE,
        packageName = ExamplesPluginPackage.NAME,
        category = PluginCategoryNames.EXAMPLES,
        shortDescription = "Plugin short description goes here.",
        description = "Plugin long description goes here.")
// @formatter:on
public class GtirbPlugin extends ProgramPlugin {

    MyProvider provider;

    /**
     * Plugin constructor.
     *
     * @param tool The plugin tool that this plugin is added to.
     */
    public GtirbPlugin(PluginTool tool) {
        super(tool, true, true);

        // TODO: Customize provider (or remove if a provider is not desired)
        String pluginName = getName();
        provider = new MyProvider(this, pluginName);

        // TODO: Customize help (or remove if help is not desired)
        String topicName = this.getClass().getPackage().getName();
        String anchorName = "HelpAnchor";
        provider.setHelpLocation(new HelpLocation(topicName, anchorName));
    }

    @Override
    public void init() {
        super.init();

        // TODO: Acquire services if necessary
    }

    // TODO: If provider is desired, it is recommended to move it to its own file
    private static class MyProvider extends ComponentProvider {

        private JPanel panel;
        private DockingAction action;

        public MyProvider(Plugin plugin, String owner) {
            super(plugin.getTool(), owner, owner);
            buildPanel();
            createActions();
        }

        // Customize GUI
        private void buildPanel() {
            panel = new JPanel(new BorderLayout());
            JTextArea textArea = new JTextArea(5, 25);
            textArea.setEditable(false);
            panel.add(new JScrollPane(textArea));
            setVisible(true);
        }

        // TODO: Customize actions
        private void createActions() {
            action =
                    new DockingAction("My Action", getName()) {
                        @Override
                        public void actionPerformed(ActionContext context) {
                            Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
                        }
                    };
            action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
            action.setEnabled(true);
            action.markHelpUnnecessary();
            dockingTool.addLocalAction(this, action);
        }

        @Override
        public JComponent getComponent() {
            return panel;
        }
    }
}

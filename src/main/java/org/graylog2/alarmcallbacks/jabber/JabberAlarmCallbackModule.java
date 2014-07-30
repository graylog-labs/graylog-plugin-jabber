package org.graylog2.alarmcallbacks.jabber;

import org.graylog2.plugin.PluginModule;

/**
 * @author Dennis Oelkers <dennis@torch.sh>
 */
public class JabberAlarmCallbackModule extends PluginModule {
    @Override
    protected void configure() {
        registerPlugin(JabberAlarmCallbackMetadata.class);
        addAlarmCallback(JabberAlarmCallback.class);
    }
}

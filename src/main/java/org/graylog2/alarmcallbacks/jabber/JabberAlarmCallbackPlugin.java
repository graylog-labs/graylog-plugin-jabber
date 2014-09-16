package org.graylog2.alarmcallbacks.jabber;

import org.graylog2.plugin.Plugin;
import org.graylog2.plugin.PluginModule;

import java.util.Collection;
import java.util.Collections;

public class JabberAlarmCallbackPlugin implements Plugin {
    @Override
    public Collection<PluginModule> modules() {
        return Collections.<PluginModule>singleton(new JabberAlarmCallbackModule());
    }
}

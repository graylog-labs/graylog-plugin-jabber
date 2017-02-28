package org.graylog2.alarmcallbacks.jabber;

import com.google.auto.service.AutoService;
import org.graylog2.plugin.Plugin;
import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.PluginModule;

import java.util.Collection;
import java.util.Collections;

@AutoService(Plugin.class)
public class JabberAlarmCallbackPlugin implements Plugin {
    @Override
    public Collection<PluginModule> modules() {
        return Collections.<PluginModule>singleton(new JabberAlarmCallbackModule());
    }

    @Override
    public PluginMetaData metadata() {
        return new JabberAlarmCallbackMetadata();
    }
}

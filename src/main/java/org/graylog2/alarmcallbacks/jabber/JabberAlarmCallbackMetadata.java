package org.graylog2.alarmcallbacks.jabber;

import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.Version;

import java.net.URI;
import java.util.Collections;
import java.util.Set;

public class JabberAlarmCallbackMetadata implements PluginMetaData {
    private static final String PLUGIN_PROPERTIES = "org.graylog.plugins.graylog-plugin-jabber/graylog-plugin.properties";

    @Override
    public String getUniqueId() {
        return JabberAlarmCallback.class.getCanonicalName();
    }

    @Override
    public String getName() {
        return "Jabber Alarmcallback Plugin";
    }

    @Override
    public String getAuthor() {
        return "Graylog, Inc.";
    }

    @Override
    public URI getURL() {
        return URI.create("https://www.graylog.org");
    }

    @Override
    public Version getVersion() {
        return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "version", Version.from(2, 0, 0));
    }

    @Override
    public String getDescription() {
        return "Alarm callback plugin that sends all stream alerts to a defined Jabber/XMPP recipient.";
    }

    @Override
    public Version getRequiredVersion() {
        return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "graylog.version", Version.from(2, 2, 0));
    }

    @Override
    public Set<ServerStatus.Capability> getRequiredCapabilities() {
        return Collections.emptySet();
    }
}

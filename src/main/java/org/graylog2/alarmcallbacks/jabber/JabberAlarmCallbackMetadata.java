package org.graylog2.alarmcallbacks.jabber;

import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.Version;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * @author Dennis Oelkers <dennis@torch.sh>
 */
public class JabberAlarmCallbackMetadata implements PluginMetaData {
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
        return "TORCH GmbH";
    }

    @Override
    public URL getURL() {
        URL url = null;
        try {
            url = new URL("http://www.torch.sh");
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        return url;
    }

    @Override
    public Version getVersion() {
        return new Version(1,0,0);
    }

    @Override
    public String getDescription() {
        return "This plugin includes an alarm callback type that sends all stream alerts to a defined recipient using jabber.";
    }

    @Override
    public Version getRequiredVersion() {
        return new Version(0,21,0);
    }
}

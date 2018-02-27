package org.graylog2.alarmcallbacks.jabber;

import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.streams.Stream;

public class JabberAlarmCallbackFormatter {
    public String render(final Stream stream, final AlertCondition.CheckResult result) {
        return "Graylog alert for stream <" + stream.getTitle() + ">\n\n"
                + "Date: " + result.getTriggeredAt() + "\n"
                + "Stream ID: " + stream.getId() + "\n"
                + "Stream title: " + stream.getTitle() + "\n"
                + "Triggered condition: " + result.getTriggeredCondition() + "\n";
    }
}

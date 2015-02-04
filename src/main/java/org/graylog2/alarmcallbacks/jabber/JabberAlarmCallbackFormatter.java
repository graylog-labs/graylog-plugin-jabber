package org.graylog2.alarmcallbacks.jabber;

import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.streams.Stream;

public class JabberAlarmCallbackFormatter {
    private final Stream stream;
    private final AlertCondition.CheckResult result;

    private transient String formatted;

    public JabberAlarmCallbackFormatter(final Stream stream, final AlertCondition.CheckResult result) {
        this.stream = stream;
        this.result = result;
    }

    private String formatAlarmNotification(final Stream stream, final AlertCondition.CheckResult result) {
        return "Graylog alert for stream <" + stream.getTitle() + ">\n\n"
                + "Date: " + result.getTriggeredAt() + "\n"
                + "Stream ID: " + stream.getId() + "\n"
                + "Stream title: " + stream.getTitle() + "\n"
                + "Triggered condition: " + result.getTriggeredCondition() + "\n";
    }

    @Override
    public String toString() {
        if (formatted == null) {
            formatted = formatAlarmNotification(stream, result);
        }

        return formatted;
    }
}

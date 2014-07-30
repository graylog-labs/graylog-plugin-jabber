package org.graylog2.alarmcallbacks.jabber;

import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.streams.Stream;

/**
 * @author Dennis Oelkers <dennis@torch.sh>
 */
public class JabberAlarmCallbackFormatter {
    private final Stream stream;
    private final AlertCondition.CheckResult result;

    private String formatted;

    public JabberAlarmCallbackFormatter(Stream stream, AlertCondition.CheckResult result) {
        this.stream = stream;
        this.result = result;
    }

    private StringBuilder formatAlarmNotification(Stream stream, AlertCondition.CheckResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("Graylog2 alert for stream <").append(stream.getTitle()).append(">\n\n")
            .append("Date: " + result.getTriggeredAt() + "\n")
            .append("Stream ID: " + stream.getId() + "\n")
            .append("Stream title: " + stream.getTitle() + "\n")
            .append("Triggered condition: " + result.getTriggeredCondition() + "\n");

        return sb;
    }

    @Override
    public String toString() {
        if (formatted == null)
            formatted = formatAlarmNotification(stream, result).toString();

        return formatted;
    }
}

package org.graylog2.alarmcallbacks.jabber;

import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.streams.Stream;
import org.joda.time.DateTime;

public class JabberAlarmCallbackFormatter {
    public String render(final Stream stream, final AlertCondition.CheckResult result) {
        final StringBuilder messageBacklog = new StringBuilder();
        if (result.getMatchingMessages().size() == 0) {
            messageBacklog.append("No message backlog available.");
        } else {
            for (MessageSummary message : result.getMatchingMessages()) {
                messageBacklog
                        .append(message.getTimestamp())
                        .append(" - ")
                        .append(message.getMessage())
                        .append("\n");
            }
        }

        final AlertCondition condition = result.getTriggeredCondition();
        final String triggeredCondition = condition == null ? "" :
                "Trigger: " + condition.getTitle() + " (" + condition.getType() + ")" + "\n"
                + "Triggered condition: " + condition + "\n";

        final DateTime resultTriggeredAt = result.getTriggeredAt();
        final String triggeredAt = resultTriggeredAt == null ? "" : "Date: " + resultTriggeredAt + "\n";

        return "Graylog alert for stream <" + stream.getTitle() + ">\n\n"
                + "Stream ID: " + stream.getId() + "\n"
                + triggeredAt
                + triggeredCondition
                + "\n"
                + "---- Messages ----" + "\n"
                + messageBacklog.toString();
    }
}

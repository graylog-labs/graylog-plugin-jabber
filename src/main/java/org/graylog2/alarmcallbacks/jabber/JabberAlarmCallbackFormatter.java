package org.graylog2.alarmcallbacks.jabber;

import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.streams.Stream;
import org.graylog2.plugin.MessageSummary;

public class JabberAlarmCallbackFormatter {
    private final Stream stream;
    private final AlertCondition.CheckResult result;

    private transient String formatted;

    public JabberAlarmCallbackFormatter(final Stream stream, final AlertCondition.CheckResult result) {
        this.stream = stream;
        this.result = result;
    }

    private String formatAlarmNotification(final Stream stream, final AlertCondition.CheckResult result) {
        String messageBacklog = "";
	if (result.getMatchingMessages().size() == 0) {
	    messageBacklog += "No message backlog available.\n";
	} else {
	    for (MessageSummary message : result.getMatchingMessages()) {
                messageBacklog += message.getMessage() + "\n";
            }
        }
        return  "\n\n"
            + "Date: " + result.getTriggeredAt() + "\n"
            + "Trigger: " + result.getTriggeredCondition().getTitle() + " ( " + result.getTriggeredCondition().getType() + " )" + "\n"
            + "Stream ID: " + stream.getId() + "\n"
            + "Stream title: " + stream.getTitle() + "\n"
            + "Triggered condition: " + result.getTriggeredCondition() + "\n\n"
            + "**********Message**********" + "\n"
            + messageBacklog;
    }

    @Override
    public String toString() {
        if (formatted == null) {
            formatted = formatAlarmNotification(stream, result);
        }

        return formatted;
    }
}

package org.graylog2.alarmcallbacks.jabber;

import org.graylog2.alerts.AbstractAlertCondition;
import org.graylog2.alerts.types.DummyAlertCondition;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.streams.Stream;
import org.joda.time.DateTime;
import org.junit.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JabberAlarmCallbackFormatterTest {
    @Test
    public void testRenderWithNegativeCheckResult() {
        final Stream mockStream = mock(Stream.class);
        when(mockStream.getTitle()).thenReturn("Stream Title");
        when(mockStream.getId()).thenReturn("001122334455667788");

        final AbstractAlertCondition.NegativeCheckResult checkResult = new AbstractAlertCondition.NegativeCheckResult();
        final JabberAlarmCallbackFormatter formatter = new JabberAlarmCallbackFormatter();

        final String s = formatter.render(mockStream, checkResult);
        assertThat(s)
                .isNotEmpty()
                .startsWith("Graylog alert for stream <Stream Title>")
                .contains("Stream ID: 001122334455667788")
                .endsWith("No message backlog available.");
    }

    @Test
    public void testRenderWithoutBacklog() {
        final Stream mockStream = mock(Stream.class);
        when(mockStream.getTitle()).thenReturn("Stream Title");
        when(mockStream.getId()).thenReturn("001122334455667788");
        when(mockStream.toString()).thenReturn("Mock-Stream-toString");

        final DummyAlertCondition alertCondition = new DummyAlertCondition(
                mockStream,
                "id",
                DateTime.parse("2018-02-27T17:00:00.000Z"),
                "admin",
                Collections.emptyMap(),
                "title"
        );
        final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
                true,
                alertCondition,
                "result-description",
                DateTime.parse("2018-02-27T17:00:00.000Z"),
                Collections.emptyList()
        );
        final JabberAlarmCallbackFormatter formatter = new JabberAlarmCallbackFormatter();

        final String s = formatter.render(mockStream, checkResult);
        assertThat(s)
                .isNotEmpty()
                .startsWith("Graylog alert for stream <Stream Title>")
                .containsSequence(
                        "Stream ID: 001122334455667788",
                        "Date: 2018-02-27T17:00:00.000Z",
                        "Trigger: title (dummy)",
                        "Triggered condition: id:dummy={Dummy alert to test notifications}, stream:={Mock-Stream-toString}")
                .endsWith("No message backlog available.");
    }

    @Test
    public void testRenderWithBacklog() {
        final Stream mockStream = mock(Stream.class);
        when(mockStream.getTitle()).thenReturn("Stream Title");
        when(mockStream.getId()).thenReturn("001122334455667788");
        when(mockStream.toString()).thenReturn("Mock-Stream-toString");

        final DummyAlertCondition alertCondition = new DummyAlertCondition(
                mockStream,
                "id",
                DateTime.parse("2018-02-27T17:00:00.000Z"),
                "admin",
                Collections.emptyMap(),
                "title"
        );
        final MessageSummary messageSummary = new MessageSummary("graylog_0", new Message("message", "source", DateTime.parse("2018-02-27T17:00:00.000Z")));
        final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
                true,
                alertCondition,
                "result-description",
                DateTime.parse("2018-02-27T17:00:00.000Z"),
                Collections.singletonList(messageSummary)
        );
        final JabberAlarmCallbackFormatter formatter = new JabberAlarmCallbackFormatter();

        final String s = formatter.render(mockStream, checkResult);
        assertThat(s)
                .isNotEmpty()
                .startsWith("Graylog alert for stream <Stream Title>")
                .containsSequence(
                        "Stream ID: 001122334455667788",
                        "Date: 2018-02-27T17:00:00.000Z",
                        "Trigger: title (dummy)",
                        "Triggered condition: id:dummy={Dummy alert to test notifications}, stream:={Mock-Stream-toString}")
                .endsWith("2018-02-27T17:00:00.000Z - message\n");
    }
}
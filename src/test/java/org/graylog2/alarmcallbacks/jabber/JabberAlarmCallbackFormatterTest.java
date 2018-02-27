package org.graylog2.alarmcallbacks.jabber;

import org.graylog2.alerts.AbstractAlertCondition;
import org.graylog2.plugin.streams.Stream;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class JabberAlarmCallbackFormatterTest {

    @Test
    public void testRender() {
        final Stream mockStream = mock(Stream.class);
        final AbstractAlertCondition.NegativeCheckResult checkResult = new AbstractAlertCondition.NegativeCheckResult();
        final JabberAlarmCallbackFormatter formatter = new JabberAlarmCallbackFormatter();

        assertThat(formatter.render(mockStream, checkResult)).isNotEmpty();
    }
}
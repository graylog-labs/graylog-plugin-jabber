package org.graylog2.alarmcallbacks.jabber;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.google.common.io.Resources;
import org.graylog2.alarmcallbacks.jabber.smack.IncomingListener;
import org.graylog2.alarmcallbacks.jabber.testcontainers.ProsodyContainer;
import org.graylog2.alerts.AbstractAlertCondition;
import org.graylog2.plugin.alarms.callbacks.AlarmCallbackException;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.streams.Stream;
import org.jivesoftware.smack.chat2.Chat;
import org.jivesoftware.smack.chat2.ChatManager;
import org.jivesoftware.smack.chat2.IncomingChatMessageListener;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
import org.jivesoftware.smack.util.TLSUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.jxmpp.jid.EntityBareJid;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static com.jayway.awaitility.Awaitility.await;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;

public class ProsodyIntegrationTest {
    static {
        final URL trustStoreURL = Resources.getResource("ssl/cacerts.jks");
        final URI trustStoreURI;
        try {
            trustStoreURI = trustStoreURL.toURI();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        final Path trustStorePath = Paths.get(trustStoreURI);
        System.setProperty("javax.net.ssl.trustStore", trustStorePath.toString());
    }

    private static final Set<Map.Entry<String, String>> USERS = ImmutableSet.<Map.Entry<String, String>>builder()
            .add(Maps.immutableEntry("user1", "example.com"))
            .add(Maps.immutableEntry("user2", "example.com"))
            .add(Maps.immutableEntry("user1", "example.net"))
            .add(Maps.immutableEntry("user2", "example.net"))
            .add(Maps.immutableEntry("user1", "example.org"))
            .add(Maps.immutableEntry("user2", "example.org"))
            .build();
    private static final String XMPP_PASSWORD = "test1234";

    @ClassRule
    public static final ProsodyContainer PROSODY = new ProsodyContainer();
    private Map<String, Object> configSource;
    private XMPPTCPConnection xmppConnection;
    private ChatManager chatManager;
    private JabberAlarmCallback callback;

    @BeforeClass
    public static void initialize() throws Exception {
        // Create users
        for (Map.Entry<String, String> entry : USERS) {
            final String username = entry.getKey();
            final String domain = entry.getValue();
            PROSODY.createUser(username, XMPP_PASSWORD, domain);
        }
    }

    @Before
    public void setUp() {
        callback = new JabberAlarmCallback();
        configSource = new HashMap<>();
        configSource.put("hostname", PROSODY.getContainerIpAddress());
        configSource.put("port", PROSODY.getMappedPort(5222));
        configSource.put("password", XMPP_PASSWORD);
    }

    @After
    public void tearDown() {
        if (callback != null) {
            callback.closeConnection();
        }
        if (xmppConnection != null && xmppConnection.isConnected()) {
            xmppConnection.instantShutdown();
        }
    }

    @Test
    public void testPlaintext() throws Exception {
        configSource.put("username", "user1");
        configSource.put("service_name", "example.org");
        configSource.put("recipient", "user2@" + "example.org");
        configSource.put("require_security", false);
        configSource.put("accept_selfsigned", false);

        xmppConnection = createConnection(
                PROSODY.getContainerIpAddress(),
                PROSODY.getMappedPort(5222),
                "user2", "example.org", XMPP_PASSWORD);
        xmppConnection.connect().login();
        chatManager = ChatManager.getInstanceFor(xmppConnection);

        final IncomingListener listener = new IncomingListener();
        chatManager.addIncomingListener(listener);

        final Configuration config = new Configuration(configSource);
        callback.initialize(config);
        callback.checkConfiguration();

        final Stream mockStream = mock(Stream.class);

        callback.call(mockStream, new AbstractAlertCondition.NegativeCheckResult());

        await().until(() -> !listener.messages.isEmpty());

        assertEquals(1, listener.messages.size());
        assertFalse(listener.messages.get("user1@" + "example.org").getBody().isEmpty());
    }

    @Test
    public void testSelfSignedAllowed() throws Exception {
        configSource.put("username", "user1");
        configSource.put("service_name", "example.net");
        configSource.put("recipient", "user2@" + "example.net");
        configSource.put("require_security", true);
        configSource.put("accept_selfsigned", true);

        xmppConnection = createConnection(
                PROSODY.getContainerIpAddress(),
                PROSODY.getMappedPort(5222),
                "user2", "example.net", XMPP_PASSWORD);
        xmppConnection.connect().login();
        chatManager = ChatManager.getInstanceFor(xmppConnection);

        final IncomingListener listener = new IncomingListener();
        chatManager.addIncomingListener(listener);

        final Configuration config = new Configuration(configSource);
        callback.initialize(config);
        callback.checkConfiguration();

        final Stream mockStream = mock(Stream.class);

        callback.call(mockStream, new AbstractAlertCondition.NegativeCheckResult());

        await().until(() -> !listener.messages.isEmpty());

        assertEquals(1, listener.messages.size());
        assertFalse(listener.messages.get("user1@" + "example.net").getBody().isEmpty());
    }

    @Test
    public void testSelfSignedNotAllowed() throws Exception {
        configSource.put("username", "user1");
        configSource.put("service_name", "example.net");
        configSource.put("recipient", "user2@" + "example.net");
        configSource.put("require_security", true);
        configSource.put("accept_selfsigned", false);

        final Configuration config = new Configuration(configSource);
        callback.initialize(config);
        callback.checkConfiguration();

        final Stream mockStream = mock(Stream.class);
        try {
            callback.call(mockStream, new AbstractAlertCondition.NegativeCheckResult());
            fail("Expected AlarmCallbackException to be thrown.");
        } catch (AlarmCallbackException e) {
            assertTrue(e.getMessage().startsWith("Unable to connect to XMPP server"));
        }
    }

    @Test
    public void testCASigned() throws Exception {
        configSource.put("username", "user1");
        configSource.put("service_name", "example.com");
        configSource.put("recipient", "user2@" + "example.com");
        configSource.put("require_security", true);
        configSource.put("accept_selfsigned", false);

        xmppConnection = createConnection(
                PROSODY.getContainerIpAddress(),
                PROSODY.getMappedPort(5222),
                "user2", "example.com", XMPP_PASSWORD);
        xmppConnection.connect().login();
        chatManager = ChatManager.getInstanceFor(xmppConnection);

        final IncomingListener listener = new IncomingListener();
        chatManager.addIncomingListener(listener);

        final Configuration config = new Configuration(configSource);
        callback.initialize(config);
        callback.checkConfiguration();

        final Stream mockStream = mock(Stream.class);

        callback.call(mockStream, new AbstractAlertCondition.NegativeCheckResult());

        await().until(() -> !listener.messages.isEmpty());

        assertEquals(1, listener.messages.size());
        assertFalse(listener.messages.get("user1@" + "example.com").getBody().isEmpty());
    }

    private XMPPTCPConnection createConnection(String host, int port, String username, String domain, String password) throws Exception {
        XMPPTCPConnectionConfiguration.Builder config = XMPPTCPConnectionConfiguration.builder()
                .setUsernameAndPassword(username, password)
                .setXmppDomain(domain)
                .setHost(host)
                .setPort(port);

        TLSUtils.acceptAllCertificates(config);

        return new XMPPTCPConnection(config.build());
    }
}

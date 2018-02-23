package org.graylog2.alarmcallbacks.jabber;

import com.google.common.annotations.VisibleForTesting;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.alarms.callbacks.AlarmCallback;
import org.graylog2.plugin.alarms.callbacks.AlarmCallbackConfigurationException;
import org.graylog2.plugin.alarms.callbacks.AlarmCallbackException;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationException;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.BooleanField;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.NumberField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.streams.Stream;
import org.jivesoftware.smack.SASLAuthentication;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
import org.jivesoftware.smack.util.TLSUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

import static com.google.common.base.Strings.isNullOrEmpty;

public class JabberAlarmCallback implements AlarmCallback {
    private static final Logger LOG = LoggerFactory.getLogger(JabberAlarmCallback.class);

    private static final String CK_HOSTNAME = "hostname";
    private static final String CK_SERVICE_NAME = "service_name";
    private static final String CK_PORT = "port";
    private static final String CK_ACCEPT_SELFSIGNED = "accept_selfsigned";
    private static final String CK_USERNAME = "username";
    private static final String CK_PASSWORD = "password";
    private static final String CK_REQUIRE_SECURITY = "require_security";
    private static final String CK_RECIPIENT = "recipient";

    private XMPPTCPConnection connection;
    private Configuration config;

    @Override
    public void initialize(final Configuration config) throws AlarmCallbackConfigurationException {
        this.config = config;
    }

    private XMPPTCPConnection login(final Configuration config) throws Exception {
        final String serviceName = isNullOrEmpty(config.getString(CK_SERVICE_NAME))
                ? config.getString(CK_HOSTNAME) : config.getString(CK_SERVICE_NAME);

        final XMPPTCPConnectionConfiguration.Builder configBuilder = XMPPTCPConnectionConfiguration.builder()
                .setHost(config.getString(CK_HOSTNAME))
                .setPort(config.getInt(CK_PORT))
                .setXmppDomain(serviceName)
                .setSendPresence(false);

        if (config.getBoolean(CK_ACCEPT_SELFSIGNED)) {
            TLSUtils.acceptAllCertificates(configBuilder);
        }

        final boolean requireSecurity = config.getBoolean(CK_REQUIRE_SECURITY);
        final XMPPTCPConnectionConfiguration.SecurityMode securityMode = requireSecurity ?
                XMPPTCPConnectionConfiguration.SecurityMode.required : XMPPTCPConnectionConfiguration.SecurityMode.ifpossible;
        configBuilder.setSecurityMode(securityMode);

        final XMPPTCPConnectionConfiguration connectionConfiguration = configBuilder.build();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Supported SASL authentications: {}", SASLAuthentication.getRegisterdSASLMechanisms());
            LOG.debug("require_security: {}", requireSecurity);
            LOG.debug("Security mode: {}", connectionConfiguration.getSecurityMode());
            LOG.debug("Socket factory: {}", connectionConfiguration.getSocketFactory());
            LOG.debug("Keystore: {}", connectionConfiguration.getKeystorePath());
            LOG.debug("Keystore type: {}", connectionConfiguration.getKeystoreType());
        }

        final XMPPTCPConnection xmppConnection = new XMPPTCPConnection(connectionConfiguration);

        xmppConnection.connect();
        xmppConnection.login(config.getString(CK_USERNAME), config.getString(CK_PASSWORD));

        return xmppConnection;
    }

    @Override
    public void call(final Stream stream, final AlertCondition.CheckResult result) throws AlarmCallbackException {
        if (connection == null || !connection.isConnected() || !connection.isAuthenticated()) {
            try {
                this.connection = login(config);
            } catch (Exception e) {
                final String serverString = String.format("%s:%d (service name: %s)",
                        config.getString(CK_HOSTNAME),
                        config.getInt(CK_PORT),
                        isNullOrEmpty(config.getString(CK_SERVICE_NAME)) ? config.getString(CK_HOSTNAME) : config.getString(CK_SERVICE_NAME)
                );
                throw new AlarmCallbackException("Unable to connect to XMPP server " + serverString, e);
            }
        }

        String messageRecipient = config.getString(CK_RECIPIENT);
        String messageBody = new JabberAlarmCallbackFormatter(stream, result).toString();
        try {
            final Message message = new Message(messageRecipient, messageBody);
            connection.sendStanza(message);
        } catch (Exception e) {
            throw new AlarmCallbackException("Unable to send message", e);
        }
    }

    @VisibleForTesting
    void closeConnection() {
        if (connection != null && connection.isConnected()) {
            connection.instantShutdown();
        }
    }

    @Override
    public ConfigurationRequest getRequestedConfiguration() {
        final ConfigurationRequest cr = new ConfigurationRequest();

        cr.addField(new TextField(CK_RECIPIENT,
                "Recipient",
                "user@server.org",
                "Recipient of Jabber messages",
                ConfigurationField.Optional.NOT_OPTIONAL));

        cr.addField(new TextField(CK_HOSTNAME,
                "Hostname",
                "localhost",
                "Hostname of Jabber server",
                ConfigurationField.Optional.NOT_OPTIONAL));

        cr.addField(new NumberField(CK_PORT,
                "Port",
                5222,
                "Port of Jabber server",
                ConfigurationField.Optional.NOT_OPTIONAL));

        cr.addField(new BooleanField(CK_REQUIRE_SECURITY,
                "Require SSL/TLS?",
                false,
                "Force encryption for the server connection?"));

        cr.addField(new BooleanField(CK_ACCEPT_SELFSIGNED,
                "Accept self-signed certificates?",
                false,
                "Do not enforce full validation of the certificate chain"));

        cr.addField(new TextField(CK_USERNAME,
                "Username",
                "jabberuser",
                "Username to connect with",
                ConfigurationField.Optional.NOT_OPTIONAL));

        cr.addField(new TextField(CK_PASSWORD,
                "Password",
                "",
                "Password to connect with",
                ConfigurationField.Optional.NOT_OPTIONAL,
                TextField.Attribute.IS_PASSWORD));

        cr.addField(new TextField(CK_SERVICE_NAME,
                "Service Name",
                "",
                "The service name of the server (hostname used if not present)",
                ConfigurationField.Optional.OPTIONAL));

        return cr;
    }

    @Override
    public String getName() {
        return "Jabber Alarm Callback";
    }

    @Override
    public Map<String, Object> getAttributes() {
        final Map<String, Object> source = config.getSource();
        final Map<String, Object> attributes = source == null ? new HashMap<>() : new HashMap<>(source);

        LOG.debug("Attributes: {}", attributes);

        if (attributes.containsKey(CK_PASSWORD)) {
            attributes.put(CK_PASSWORD, "******");
        }

        return attributes;
    }

    @Override
    public void checkConfiguration() throws ConfigurationException {
        if (!config.stringIsSet(CK_RECIPIENT)) {
            throw new ConfigurationException("Mandatory field " + CK_RECIPIENT + " is missing.");
        }

        if (!config.stringIsSet(CK_HOSTNAME)) {
            throw new ConfigurationException("Mandatory field " + CK_RECIPIENT + " is missing.");
        }

        if (!config.intIsSet(CK_PORT)) {
            throw new ConfigurationException("Mandatory field " + CK_PORT + " is missing.");
        }

        if (!config.stringIsSet(CK_USERNAME)) {
            throw new ConfigurationException("Mandatory field " + CK_USERNAME + " is missing.");
        }

        if (!config.stringIsSet(CK_PASSWORD)) {
            throw new ConfigurationException("Mandatory field " + CK_PASSWORD + " is missing.");
        }

        final long port = config.getInt(CK_PORT);
        if (1 < port && port > 65535) {
            throw new ConfigurationException(CK_PORT + " must be between 1 and 65535.");
        }
    }
}

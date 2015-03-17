package org.graylog2.alarmcallbacks.jabber;

import com.google.common.collect.Maps;
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
import org.jivesoftware.smack.Chat;
import org.jivesoftware.smack.ChatManager;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.SASLAuthentication;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
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

    private XMPPConnection connection;
    private Configuration config;

    @Override
    public void initialize(final Configuration config) throws AlarmCallbackConfigurationException {
        this.config = config;
    }

    private XMPPConnection login(final Configuration config) throws IOException, XMPPException, SmackException {
        final String serviceName = isNullOrEmpty(config.getString(CK_SERVICE_NAME))
                ? config.getString(CK_HOSTNAME) : config.getString(CK_SERVICE_NAME);

        final ConnectionConfiguration connectionConfiguration = new ConnectionConfiguration(
                config.getString(CK_HOSTNAME),
                config.getInt(CK_PORT),
                serviceName
        );

        connectionConfiguration.setSendPresence(false);

        if (config.getBoolean(CK_ACCEPT_SELFSIGNED)) {
            connectionConfiguration.setCustomSSLContext(getTrustAllSSLContext());
        }

        connectionConfiguration.setSecurityMode(config.getBoolean(CK_REQUIRE_SECURITY) ?
                ConnectionConfiguration.SecurityMode.required : ConnectionConfiguration.SecurityMode.enabled);

        LOG.debug("Supported SASL authentications: " + SASLAuthentication.getRegisterSASLMechanisms());

        LOG.debug("require_security: " + config.getBoolean(CK_REQUIRE_SECURITY));
        LOG.debug("Security mode: " + connectionConfiguration.getSecurityMode());
        LOG.debug("Socket factory: " + connectionConfiguration.getSocketFactory());
        LOG.debug("Keystore: " + connectionConfiguration.getKeystorePath());
        LOG.debug("Keystore type: " + connectionConfiguration.getKeystoreType());

        final XMPPConnection xmppConnection = new XMPPTCPConnection(connectionConfiguration);

        xmppConnection.connect();
        xmppConnection.login(config.getString(CK_USERNAME), config.getString(CK_PASSWORD));

        return xmppConnection;
    }

    private SSLContext getTrustAllSSLContext() {
        final TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
        };

        try {
            final SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            return sc;
        } catch (GeneralSecurityException e) {
            LOG.error("Unable to initialize SSL context: {}", e);
            return null;
        }
    }

    @Override
    public void call(final Stream stream, final AlertCondition.CheckResult result) throws AlarmCallbackException {
        if (connection == null || !connection.isConnected() || !connection.isAuthenticated()) {
            try {
                this.connection = login(config);
            } catch (XMPPException | SmackException | IOException e) {
                throw new AlarmCallbackException("Unable to connect to jabber server: ", e);
            }
        }

        final Chat chat = ChatManager.getInstanceFor(connection).createChat(config.getString(CK_RECIPIENT), null);
        try {
            chat.sendMessage(new JabberAlarmCallbackFormatter(stream, result).toString());
        } catch (XMPPException | SmackException.NotConnectedException e) {
            throw new AlarmCallbackException("Unable to send message: ", e);
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
        final Map<String, Object> attributes = Maps.newHashMap(config.getSource());
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

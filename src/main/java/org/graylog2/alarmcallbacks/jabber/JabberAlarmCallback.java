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
import org.jivesoftware.smack.*;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;

/**
 * @author Dennis Oelkers <dennis@torch.sh>
 */
public class JabberAlarmCallback implements AlarmCallback {
    private final Logger LOG = LoggerFactory.getLogger(JabberAlarmCallback.class);
    private XMPPConnection connection;
    private Configuration config;

    public JabberAlarmCallback() {
    }

    @Override
    public void initialize(Configuration config) throws AlarmCallbackConfigurationException {
        this.config = config;
    }

    private XMPPConnection login(Configuration config) throws IOException, XMPPException, SmackException {
        final String serviceName = (config.getString("service_name") == null || !config.getString("service_name").isEmpty()
                ? config.getString("hostname")
                : config.getString("service_name"));

        ConnectionConfiguration connectionConfiguration = new ConnectionConfiguration(
                config.getString("hostname"),
                (int)config.getInt("port"),
                serviceName
        );

        connectionConfiguration.setSendPresence(false);

        if (config.getBoolean("accept_selfsigned"))
            connectionConfiguration.setCustomSSLContext(getTrustAllSSLContext());

        connectionConfiguration.setSecurityMode(config.getBoolean("require_security") ?
                ConnectionConfiguration.SecurityMode.required : ConnectionConfiguration.SecurityMode.enabled);

        LOG.debug("Supported SASL authentications: " + SASLAuthentication.getRegisterSASLMechanisms());

        LOG.debug("require_security: " + config.getBoolean("require_security"));
        LOG.debug("Security mode: " + connectionConfiguration.getSecurityMode());
        LOG.debug("Socket factory: " + connectionConfiguration.getSocketFactory());
        LOG.debug("Keystore: " + connectionConfiguration.getKeystorePath());
        LOG.debug("Keystore type: " + connectionConfiguration.getKeystoreType());

        XMPPConnection xmppConnection = new XMPPTCPConnection(connectionConfiguration);

        xmppConnection.connect();
        xmppConnection.login(config.getString("username"), config.getString("password"));

        return xmppConnection;
    }

    private SSLContext getTrustAllSSLContext() {
        TrustManager[] trustAllCerts = new TrustManager[] {
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
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            return sc;
        } catch (GeneralSecurityException e) {
            LOG.error("Unable to initialize SSL context: {}", e);
            return null;
        }
    }

    @Override
    public void call(Stream stream, AlertCondition.CheckResult result) throws AlarmCallbackException {
        if (connection == null || !connection.isConnected() || !connection.isAuthenticated()) {
            try {
                this.connection = login(config);
            } catch (XMPPException | SmackException | IOException e) {
                throw new AlarmCallbackException("Unable to connect to jabber server: ", e);
            }
        }

        Chat chat = ChatManager.getInstanceFor(connection).createChat(config.getString("recipient"), null);
        try {
            chat.sendMessage(new JabberAlarmCallbackFormatter(stream, result).toString());
        } catch (XMPPException | SmackException.NotConnectedException e) {
            throw new AlarmCallbackException("Unable to send message: ", e);
        }
    }

    @Override
    public ConfigurationRequest getRequestedConfiguration() {
        ConfigurationRequest cr = new ConfigurationRequest();

        cr.addField(new TextField("recipient",
                "Recipient",
                "user@server.org",
                "Recipient of Jabber messages",
                ConfigurationField.Optional.NOT_OPTIONAL));

        cr.addField(new TextField("hostname",
                "Hostname",
                "localhost",
                "Hostname of Jabber server",
                ConfigurationField.Optional.NOT_OPTIONAL));

        cr.addField(new NumberField("port",
                "Port",
                5222,
                "Port of Jabber server",
                ConfigurationField.Optional.NOT_OPTIONAL));

        cr.addField(new BooleanField("require_security",
                "Require SSL/TLS?",
                false,
                "Force encryption for the server connection?"));

        cr.addField(new BooleanField("accept_selfsigned",
                "Accept self-signed certificates?",
                false,
                "Do not enforce full validation of the certificate chain"));

        cr.addField(new TextField("username",
                "Username",
                "jabberuser",
                "Username to connect with",
                ConfigurationField.Optional.NOT_OPTIONAL));

        cr.addField(new TextField("password",
                "Password",
                "",
                "Password to connect with",
                ConfigurationField.Optional.NOT_OPTIONAL,
                TextField.Attribute.IS_PASSWORD));

        cr.addField(new TextField("service_name",
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
        Map<String, Object> attributes = Maps.newHashMap();
        attributes.putAll(config.getSource());

        LOG.info("Attributes: {}", attributes);

        if (attributes.containsKey("password"))
            attributes.put("password", "******");

        return attributes;
    }

    @Override
    public void checkConfiguration() throws ConfigurationException {
    }
}
